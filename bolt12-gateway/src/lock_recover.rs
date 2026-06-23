// SPDX-License-Identifier: MIT
//! Poison-safe `std::sync::Mutex` helper.
//!
//! If any thread
//! panics while holding a `std::sync::Mutex` (for example inside an
//! LDK callback that hits an `assert!`), every subsequent caller
//! that uses `.expect("…poisoned")` panics too. The gateway process
//! is shared across all BOLT 12 wallet operations, so a single
//! crafted malformed message could `DoS` the whole surface.
//!
//! This helper recovers the inner guard from a poisoned lock,
//! preserving liveness at the cost of accepting potentially
//! inconsistent inner state. Call sites that rely on inner
//! invariants must validate them after lock acquisition.

use std::sync::{Mutex, MutexGuard};

/// Acquire `m`, recovering the inner guard if the mutex is poisoned.
pub fn lock_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// regression: a panic inside the critical section must not
    /// permanently disable subsequent callers.
    #[test]
    fn lock_recover_returns_inner_after_poison() {
        let m = Arc::new(Mutex::new(0u32));
        let m2 = Arc::clone(&m);
        let _ = thread::spawn(move || {
            let mut g = m2.lock().expect("first acquire");
            *g = 42;
            panic!("poison the mutex");
        })
        .join();
        // std::sync::Mutex is now poisoned; lock_recover must still
        // return the inner value the panicking thread left behind.
        let g = lock_recover(&m);
        assert_eq!(*g, 42);
    }
}
