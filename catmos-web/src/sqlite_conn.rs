//! Shared SQLite connection wrapper for WASM (OPFS SAH VFS + sqlite3mc ChaCha20).
//!
//! Provides `SqliteConn` — a thin safe wrapper around the raw `sqlite3*` handle
//! from `sqlite-wasm-rs`. Used by:
//!   - `mls_storage.rs` — OpenMLS KV storage
//!   - `storage.rs` — conversation/message/sync storage
//!   - `credentials.rs` — credential storage
//!
//! All three share the same encrypted database file when the connection is
//! created once in `wasm_init()` and passed via `Rc`.

use sqlite_wasm_rs::*;
use std::ffi::CString;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the WASM SQLite storage layer.
#[derive(Debug, thiserror::Error)]
pub enum WasmSqliteError {
    #[error("SQLite error ({code}): {message}")]
    Sqlite { code: i32, message: String },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Null pointer from SQLite")]
    NullPointer,
}

impl From<serde_json::Error> for WasmSqliteError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// SQLITE_TRANSIENT helper
// ---------------------------------------------------------------------------

/// Returns the SQLITE_TRANSIENT destructor constant, which tells SQLite to
/// make its own copy of the data immediately.
///
/// In the C API this is defined as `((sqlite3_destructor_type)-1)`.
pub fn sqlite_transient() -> Option<unsafe extern "C" fn(*mut std::ffi::c_void)> {
    // SQLITE_TRANSIENT = ((sqlite3_destructor_type)-1)
    unsafe {
        Some(std::mem::transmute::<isize, unsafe extern "C" fn(*mut std::ffi::c_void)>(-1))
    }
}

// ---------------------------------------------------------------------------
// Safe SQLite wrapper (thin layer over sqlite-wasm-rs raw FFI)
// ---------------------------------------------------------------------------

/// Safe wrapper around a raw `sqlite3*` handle.
///
/// All methods that operate on the database are `&self` because SQLite compiled
/// with `SQLITE_THREADSAFE=0` is single-threaded (fine for WASM).
pub struct SqliteConn {
    db: *mut sqlite3,
}

impl SqliteConn {
    /// Open a database at the given path with sqlite3mc ChaCha20 encryption.
    ///
    /// - `db_path` -- file path for the database (e.g. `"catmos-app.db"`)
    /// - `key` -- hex-encoded 256-bit key for sqlite3mc ChaCha20 encryption
    ///
    /// Does NOT create any tables — the caller is responsible for schema setup.
    pub fn open(db_path: &str, key: &str) -> Result<Self, WasmSqliteError> {
        let c_path =
            CString::new(db_path).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut db: *mut sqlite3 = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_open_v2(
                c_path.as_ptr().cast(),
                &mut db as *mut _,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                std::ptr::null(),
            )
        };

        if ret != SQLITE_OK || db.is_null() {
            return Err(WasmSqliteError::Sqlite {
                code: ret,
                message: "Failed to open database".to_string(),
            });
        }

        let conn = Self { db };

        // Configure sqlite3mc encryption
        conn.exec_raw(&format!("PRAGMA key = '{}';", key))?;
        conn.exec_raw("PRAGMA cipher = 'chacha20';")?;
        conn.exec_raw("PRAGMA page_size = 4096;")?;

        Ok(conn)
    }

    /// Execute a SQL statement with no parameters and no result.
    pub fn exec_raw(&self, sql: &str) -> Result<(), WasmSqliteError> {
        let c_sql =
            CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let ret = unsafe {
            sqlite3_exec(
                self.db,
                c_sql.as_ptr().cast(),
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }
        Ok(())
    }

    /// Read a value by key from a KV-style table (used by OpenMLS storage).
    pub fn get(&self, storage_key: &[u8]) -> Result<Option<Vec<u8>>, WasmSqliteError> {
        let sql = c"SELECT value FROM openmls_kv WHERE storage_key = ?1";
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        let ret = unsafe {
            sqlite3_bind_blob(
                stmt,
                1,
                storage_key.as_ptr().cast(),
                storage_key.len() as i32,
                sqlite_transient(),
            )
        };
        if ret != SQLITE_OK {
            unsafe { sqlite3_finalize(stmt) };
            return Err(self.last_error(ret));
        }

        let step = unsafe { sqlite3_step(stmt) };
        let result = if step == SQLITE_ROW {
            let blob_ptr = unsafe { sqlite3_column_blob(stmt, 0) };
            let blob_len = unsafe { sqlite3_column_bytes(stmt, 0) } as usize;
            if blob_ptr.is_null() || blob_len == 0 {
                Ok(Some(Vec::new()))
            } else {
                let slice =
                    unsafe { std::slice::from_raw_parts(blob_ptr.cast::<u8>(), blob_len) };
                Ok(Some(slice.to_vec()))
            }
        } else if step == SQLITE_DONE {
            Ok(None)
        } else {
            Err(self.last_error(step))
        };

        unsafe { sqlite3_finalize(stmt) };
        result
    }

    /// Upsert a key-value pair (INSERT OR REPLACE) into the KV table.
    pub fn put(&self, storage_key: &[u8], value: &[u8]) -> Result<(), WasmSqliteError> {
        let sql =
            c"INSERT OR REPLACE INTO openmls_kv (storage_key, value) VALUES (?1, ?2)";
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        let ret = unsafe {
            sqlite3_bind_blob(
                stmt,
                1,
                storage_key.as_ptr().cast(),
                storage_key.len() as i32,
                sqlite_transient(),
            )
        };
        if ret != SQLITE_OK {
            unsafe { sqlite3_finalize(stmt) };
            return Err(self.last_error(ret));
        }

        let ret = unsafe {
            sqlite3_bind_blob(
                stmt,
                2,
                value.as_ptr().cast(),
                value.len() as i32,
                sqlite_transient(),
            )
        };
        if ret != SQLITE_OK {
            unsafe { sqlite3_finalize(stmt) };
            return Err(self.last_error(ret));
        }

        let step = unsafe { sqlite3_step(stmt) };
        unsafe { sqlite3_finalize(stmt) };

        if step != SQLITE_DONE {
            return Err(self.last_error(step));
        }
        Ok(())
    }

    /// Delete a key from the KV table.
    pub fn remove(&self, storage_key: &[u8]) -> Result<(), WasmSqliteError> {
        let sql = c"DELETE FROM openmls_kv WHERE storage_key = ?1";
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        let ret = unsafe {
            sqlite3_bind_blob(
                stmt,
                1,
                storage_key.as_ptr().cast(),
                storage_key.len() as i32,
                sqlite_transient(),
            )
        };
        if ret != SQLITE_OK {
            unsafe { sqlite3_finalize(stmt) };
            return Err(self.last_error(ret));
        }

        let step = unsafe { sqlite3_step(stmt) };
        unsafe { sqlite3_finalize(stmt) };

        if step != SQLITE_DONE {
            return Err(self.last_error(step));
        }
        Ok(())
    }

    /// Prepare a SQL statement, bind text parameters, execute, and return nothing.
    ///
    /// `params` is a list of `(index, value)` pairs where index is 1-based.
    pub fn exec_with_text_params(
        &self,
        sql: &str,
        params: &[(i32, &str)],
    ) -> Result<(), WasmSqliteError> {
        let c_sql =
            CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let step = unsafe { sqlite3_step(stmt) };
        unsafe { sqlite3_finalize(stmt) };

        if step != SQLITE_DONE {
            return Err(self.last_error(step));
        }
        Ok(())
    }

    /// Prepare a SQL statement, bind text and integer parameters, execute.
    pub fn exec_with_mixed_params(
        &self,
        sql: &str,
        text_params: &[(i32, &str)],
        int_params: &[(i32, i64)],
    ) -> Result<(), WasmSqliteError> {
        let c_sql =
            CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in text_params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        for &(idx, val) in int_params {
            let ret = unsafe { sqlite3_bind_int64(stmt, idx, val) };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let step = unsafe { sqlite3_step(stmt) };
        unsafe { sqlite3_finalize(stmt) };

        if step != SQLITE_DONE {
            return Err(self.last_error(step));
        }
        Ok(())
    }

    /// Prepare a SQL statement, bind text and blob parameters, execute.
    pub fn exec_with_text_and_blob_params(
        &self,
        sql: &str,
        text_params: &[(i32, &str)],
        blob_params: &[(i32, &[u8])],
    ) -> Result<(), WasmSqliteError> {
        let c_sql =
            CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in text_params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        for &(idx, val) in blob_params {
            let ret = unsafe {
                sqlite3_bind_blob(
                    stmt,
                    idx,
                    val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let step = unsafe { sqlite3_step(stmt) };
        unsafe { sqlite3_finalize(stmt) };

        if step != SQLITE_DONE {
            return Err(self.last_error(step));
        }
        Ok(())
    }

    /// Query rows with text params. Returns column values as strings for each row.
    pub fn query_text(
        &self,
        sql: &str,
        params: &[(i32, &str)],
        col_count: usize,
    ) -> Result<Vec<Vec<Option<String>>>, WasmSqliteError> {
        let c_sql =
            CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let mut rows = Vec::new();
        loop {
            let step = unsafe { sqlite3_step(stmt) };
            if step == SQLITE_ROW {
                let mut row = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let ptr = unsafe { sqlite3_column_text(stmt, i as i32) };
                    if ptr.is_null() {
                        row.push(None);
                    } else {
                        let c_str = unsafe { std::ffi::CStr::from_ptr(ptr.cast()) };
                        row.push(Some(c_str.to_string_lossy().into_owned()));
                    }
                }
                rows.push(row);
            } else if step == SQLITE_DONE {
                break;
            } else {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(step));
            }
        }

        unsafe { sqlite3_finalize(stmt) };
        Ok(rows)
    }

    /// Query rows with mixed text/int params. Returns column values as strings.
    pub fn query_text_mixed(
        &self,
        sql: &str,
        text_params: &[(i32, &str)],
        int_params: &[(i32, i64)],
        col_count: usize,
    ) -> Result<Vec<Vec<Option<String>>>, WasmSqliteError> {
        let c_sql =
            CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in text_params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        for &(idx, val) in int_params {
            let ret = unsafe { sqlite3_bind_int64(stmt, idx, val) };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let mut rows = Vec::new();
        loop {
            let step = unsafe { sqlite3_step(stmt) };
            if step == SQLITE_ROW {
                let mut row = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let ptr = unsafe { sqlite3_column_text(stmt, i as i32) };
                    if ptr.is_null() {
                        row.push(None);
                    } else {
                        let c_str = unsafe { std::ffi::CStr::from_ptr(ptr.cast()) };
                        row.push(Some(c_str.to_string_lossy().into_owned()));
                    }
                }
                rows.push(row);
            } else if step == SQLITE_DONE {
                break;
            } else {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(step));
            }
        }

        unsafe { sqlite3_finalize(stmt) };
        Ok(rows)
    }

    /// Query that returns blob data from column 0.
    pub fn query_blob(
        &self,
        sql: &str,
        text_params: &[(i32, &str)],
    ) -> Result<Option<Vec<u8>>, WasmSqliteError> {
        let c_sql =
            CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in text_params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let step = unsafe { sqlite3_step(stmt) };
        let result = if step == SQLITE_ROW {
            let blob_ptr = unsafe { sqlite3_column_blob(stmt, 0) };
            let blob_len = unsafe { sqlite3_column_bytes(stmt, 0) } as usize;
            if blob_ptr.is_null() || blob_len == 0 {
                Ok(Some(Vec::new()))
            } else {
                let slice =
                    unsafe { std::slice::from_raw_parts(blob_ptr.cast::<u8>(), blob_len) };
                Ok(Some(slice.to_vec()))
            }
        } else if step == SQLITE_DONE {
            Ok(None)
        } else {
            Err(self.last_error(step))
        };

        unsafe { sqlite3_finalize(stmt) };
        result
    }

    /// Check if a row exists (returns true if query returns at least one row).
    pub fn exists(
        &self,
        sql: &str,
        params: &[(i32, &str)],
    ) -> Result<bool, WasmSqliteError> {
        let rows = self.query_text(sql, params, 1)?;
        Ok(!rows.is_empty())
    }

    /// Extract the last error message from the database handle.
    pub fn last_error(&self, code: i32) -> WasmSqliteError {
        let msg = unsafe {
            let ptr = sqlite3_errmsg(self.db);
            if ptr.is_null() {
                "unknown error".to_string()
            } else {
                let c_str = std::ffi::CStr::from_ptr(ptr.cast());
                c_str.to_string_lossy().into_owned()
            }
        };
        WasmSqliteError::Sqlite { code, message: msg }
    }
}

impl Drop for SqliteConn {
    fn drop(&mut self) {
        if !self.db.is_null() {
            unsafe {
                sqlite3_close(self.db);
            }
        }
    }
}
