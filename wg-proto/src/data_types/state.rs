//! Peer states.

use crate::crypto::tai64::Tai64N;
use core::cmp::max;

use super::traits::Counter;

#[derive(Debug)]
pub struct InitialHandshakeData {
    pub sender_index: u32,
    pub hash: [u8; 32],
    pub chaining_key: [u8; 32],
}

#[derive(Debug)]
pub struct ReadyData {
    pub sending_key: [u8; 32],
    pub receiving_key: [u8; 32],
    pub sending_key_counter: SenderCounter,
    pub receiving_key_counter: CounterWindow,
    pub receiver_index: [u8; 4],
}

impl ReadyData {
    pub fn new(sending_key: [u8; 32], receiving_key: [u8; 32], receiver_index: [u8; 4]) -> Self {
        Self {
            sending_key,
            receiving_key,
            sending_key_counter: SenderCounter::new(),
            receiving_key_counter: CounterWindow::new(),
            receiver_index,
        }
    }
}

#[derive(Debug)]
pub enum PeerState {
    Uninintialized,
    InitialHandshake(InitialHandshakeData),
    WantsCookieReply,
    // NeedCookieReply,
    Ready(Box<ReadyData>),
}

/// Receiver counter window.
///
/// Stores the last 2000 received counter values in optimized way. Costs 8KB of memory
/// but allows to quickly check (O(1)) if the counter has been already received.
///
/// You may find simmilarities with the bloom filter, but the bloom filter is not suitable for
/// this case because it has a false positive rate, which is not acceptable for the counter
/// values.
///
/// Needed for replay attacks protection and to account for UDP packet reordering.
///
/// Memory representation:
///
/// ```plaintext
///      (1k len)          (1k len)
/// [    window 1    ][    window 2    ]
///         ^ current bounds ^
/// ```
///
/// The window is divided into two parts, each 1000 elements long. The first part is the oldest
/// part of the window, the second part is the newest part of the window. Such division allows to
/// prevent window erasure on window bounds overflow.
pub struct CounterWindow {
    window: [u64; 2000],
    max_counter: u64,
}

impl Default for CounterWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl CounterWindow {
    pub fn new() -> Self {
        // Fix for 0 counter value.
        let mut window = [0; 2000];
        window[0] = 1;

        Self {
            window,
            max_counter: 0,
        }
    }

    pub fn new_with_max_counter(max_counter: u64) -> Self {
        let mut window = [0; 2000];
        window[0] = 1;

        Self {
            window,
            max_counter,
        }
    }

    fn value_index(&self, value: u64) -> usize {
        let local_index = value % 1000;
        let top_bound = max(2000, self.max_counter);
        let normalized_second_windows_bottom = top_bound - (top_bound % 1000);
        if normalized_second_windows_bottom <= value {
            // The value is in the second window.
            (1000 + local_index) as usize
        } else {
            // The value is in the first window.
            local_index as usize
        }
    }

    pub fn put(&mut self, value: u64) -> Option<()> {
        // Update the max counter value.
        if value > self.max_counter {
            self.max_counter = value;
        }
        // Calculate the top bound of the window.
        let top_bound = max(2000, self.max_counter);
        // Check if the value is in the window bounds.
        if value < top_bound - 2000 {
            // The value is too old, discard it.
            return None;
        }
        // The value is in the window bounds, but may be already in the window.
        let index = self.value_index(value);
        if self.window[index] == value {
            // The value is already in the window.
            return None;
        }
        // The value is not in the window, put it in the window.
        self.window[index] = value;
        Some(())
    }

    /// Check if the value is in the window.
    pub fn contains(&self, value: u64) -> bool {
        // Check if the value is in the window bounds.
        if value < self.max_counter - 2000 {
            return false;
        }
        self.window[self.value_index(value)] == value
    }
}

impl core::fmt::Debug for CounterWindow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CounterWindow")
            .field("max_counter", &self.max_counter)
            .finish()
    }
}

/// Sender counter.
#[derive(Debug)]
pub struct SenderCounter(u64);

impl Default for SenderCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl SenderCounter {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn with_initial_value(initial_value: u64) -> Self {
        Self(initial_value)
    }
}

impl Counter for SenderCounter {
    fn next_counter(&mut self) -> u64 {
        let counter = self.0;
        self.0 += 1;
        counter
    }
}

#[derive(Debug)]
pub struct Peer<T: Tai64N> {
    pub greatest_seen_timestamp: T,
    pub state: PeerState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_window() {
        let mut window = CounterWindow::new();
        for i in 0..3000 {
            assert_eq!(window.put(i as u64), Some(()));
        }
        for i in 1000..3000 {
            assert!(window.contains(i as u64));
        }
        for i in 0..1000 {
            assert!(!window.contains(i as u64));
        }
        assert_eq!(window.put(3001), Some(()));
        assert!(!window.contains(1000));
    }
}
