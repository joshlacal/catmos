import type { Message } from './tauri.ts';
import { foldReactionsByAccount } from './did.ts';

type ReadPage = (before: string) => Promise<Message[]>;

/** Reload the full range already visible, including rows beyond the most recent page. */
export async function readMessageWindow(previous: Message[], first: Message[], readOlder: ReadPage) {
	const previousSeqs = previous.flatMap((m) => m.sequenceNumber && m.sequenceNumber > 0 ? [m.sequenceNumber] : []);
	const floor = previousSeqs.reduce((min, seq) => Math.min(min, seq), Infinity);
	const rows = new Map<string, Message>();
	let page = first;
	let before = Infinity;
	while (page.length) {
		for (const row of page) rows.set(row.id, row);
		const oldest = page.reduce((min, row) => Math.min(min, row.sequenceNumber || Infinity), Infinity);
		if (page.length < 50 || oldest <= floor || oldest >= before) break;
		before = oldest;
		page = await readOlder(String(before));
	}
	return Array.from(rows.values());
}

export function reconcileMessages(current: Message[], stored: Message[]): Message[] {
	const previous = new Map(current.map((row) => [row.id, row]));
	const result = stored.map((row) => {
		const reactions = row.reactions ?? previous.get(row.id)?.reactions;
		return reactions ? { ...row, reactions: foldReactionsByAccount(reactions) } : row;
	});
	for (const row of current) {
		if (row.id.startsWith('temp-') && (row.status === 'sending' || row.status === 'failed')) result.push(row);
	}
	return result.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
}
