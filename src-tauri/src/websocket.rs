use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tauri::{AppHandle, Emitter};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use catbird_mls::orchestrator::subscription::{SubscriptionDispatchOutcome, SubscriptionTicket};

use crate::recovery::{actionable_error, classify_error, RecoveryCategory};
use crate::{commands, CatmosOrchestrator};

macro_rules! log_ws {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        let ts = chrono::Local::now().format("%H:%M:%S%.3f");
        let line = format!("[catmos {}] [WS] {}\n", ts, msg);
        commands::append_log_line(&line);
    }};
}

/// Run the canonical `subscribeEvents` stream for the signed-in actor device,
/// reconnecting with exponential backoff until `shutdown` fires or the error
/// is not retryable.
///
/// The stream carries every conversation the actor belongs to, and its durable
/// cursor fence is keyed by actor device, so exactly one stream may run per
/// actor: a second concurrent stream would supersede the first one's fence.
pub async fn subscribe_all(
    app: AppHandle,
    orchestrator: Arc<CatmosOrchestrator>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut attempt = 0u32;

    loop {
        if *shutdown.borrow() {
            log_ws!("Shutdown detected");
            break;
        }

        attempt += 1;
        log_ws!("Connecting attempt {}", attempt);

        match do_subscribe(&app, &orchestrator, &mut shutdown).await {
            Ok(()) => attempt = 0,
            Err(e) => {
                log_ws!("Subscription error: {}", e);
                let category = classify_error(&e);
                let _ = app.emit("mls-ws-recovery", actionable_error(&e));
                if category != RecoveryCategory::Retry {
                    log_ws!(
                        "Stopping reconnect loop after {} recovery classification",
                        category
                    );
                    break;
                }
            }
        }

        if *shutdown.borrow() {
            log_ws!("Shutdown detected after disconnect");
            break;
        }

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 30s (spec §10)
        let delay = std::cmp::min(1 << attempt.min(5), 30);
        log_ws!("Reconnecting in {}s", delay);
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(delay)) => {},
            _ = shutdown.changed() => {
                log_ws!("Shutdown during backoff");
                break;
            },
        }
    }
}

/// One connection session. Every session re-synchronizes the authenticated
/// inventory, obtains a fresh ticket, and re-installs the durable cursor fence
/// before connecting; the orchestrator owns cursor progress from then on.
async fn do_subscribe(
    app: &AppHandle,
    orchestrator: &Arc<CatmosOrchestrator>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let ticket = orchestrator
        .prepare_subscription()
        .await
        .map_err(|e| format!("Failed to prepare subscription ticket: {e}"))?;
    orchestrator
        .initialize_subscription_cursor(&ticket)
        .await
        .map_err(|e| format!("Failed to initialize subscription cursor: {e}"))?;

    log_ws!("Connecting to {}", ticket.endpoint);
    let (stream, _) = crate::runtime_fixture::connect_websocket(&subscription_url(&ticket))
        .await
        .map_err(|e| format!("WebSocket connect failed: {e}"))?;
    log_ws!("Connected");
    let (mut write, mut read) = stream.split();

    loop {
        let frame = tokio::select! {
            _ = shutdown.changed() => {
                log_ws!("Shutdown signal received, closing WebSocket");
                return Ok(());
            }
            frame = read.next() => frame,
        };
        let Some(frame) = frame else {
            log_ws!("WebSocket stream ended");
            return Ok(());
        };
        let outcome = match frame.map_err(|e| format!("WebSocket read error: {e}"))? {
            WsMessage::Text(text) => orchestrator.apply_subscription_frame(text.as_str()).await,
            WsMessage::Binary(bytes) => orchestrator.apply_subscription_frame_bytes(&bytes).await,
            WsMessage::Ping(payload) => {
                write
                    .send(WsMessage::Pong(payload))
                    .await
                    .map_err(|e| format!("WebSocket pong failed: {e}"))?;
                continue;
            }
            WsMessage::Close(_) => {
                log_ws!("WebSocket closed by server");
                return Ok(());
            }
            WsMessage::Pong(_) | WsMessage::Frame(_) => continue,
        }
        .map_err(|e| format!("Failed to apply subscription frame: {e}"))?;
        dispatch(app, orchestrator, outcome);
    }
}

fn subscription_url(ticket: &SubscriptionTicket) -> String {
    format!(
        "{}?ticket={}&cursor={}",
        ticket.endpoint,
        urlencoding::encode(&ticket.ticket),
        urlencoding::encode(&ticket.event_cursor)
    )
}

/// Project an applied frame onto the UI. Cursor progress and state
/// reconciliation already happened inside `apply_subscription_frame`.
fn dispatch(
    app: &AppHandle,
    orchestrator: &Arc<CatmosOrchestrator>,
    outcome: SubscriptionDispatchOutcome,
) {
    match outcome {
        SubscriptionDispatchOutcome::MessageAvailable {
            conversation_id,
            target_seq,
            messages,
            ..
        } => {
            log_ws!(
                "{} message(s) available in {} through seq {}",
                messages.len(),
                conversation_id,
                target_seq
            );
            for message in messages {
                let ui_msg = commands::ui_message_from_orchestrator(message);
                let _ = app.emit("mls-incoming-message", &ui_msg);
            }
        }
        SubscriptionDispatchOutcome::Typing {
            conversation_id,
            sender_did,
            is_typing,
        } => {
            let _ = app.emit(
                "mls-typing-event",
                &commands::TypingEvent {
                    conversation_id,
                    sender_did,
                    is_typing,
                },
            );
        }
        SubscriptionDispatchOutcome::Watermark { issued_at, .. } => {
            log_ws!("Watermark issued at {}", issued_at);
        }
        SubscriptionDispatchOutcome::AccessEnded {
            user_did,
            device_id,
            ..
        } => {
            log_ws!("Access ended for {} device {}", user_did, device_id);
        }
        SubscriptionDispatchOutcome::OtherEvent {
            event_type,
            conversation_id,
            ..
        } => {
            // The event is a hint that group state moved; the HTTP sync path
            // walks commits forward from the local epoch.
            log_ws!(
                "{} for {:?}, scheduling sync",
                event_type,
                conversation_id
            );
            let orchestrator = Arc::clone(orchestrator);
            let app = app.clone();
            tokio::spawn(async move {
                match orchestrator.sync_with_server(false).await {
                    Ok(()) => {
                        let _ = app.emit("mls-tree-changed", &conversation_id);
                    }
                    Err(e) => log_ws!("Sync after {} failed: {:?}", event_type, e),
                }
            });
        }
    }
}
