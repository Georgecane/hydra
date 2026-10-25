//! A bounded, in-memory mailbox used by controlled transport experiments.
//! This module does not open sockets or connect to external services.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_QUEUE_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EndpointId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxError {
    InvalidCapacity,
    IdExhausted,
    PeerUnavailable,
    Full,
    TooLarge,
    Timeout,
    Closed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct MailboxMessage {
    pub from: EndpointId,
    pub correlation_id: u64,
    pub bytes: Vec<u8>,
}

struct Inner {
    mailboxes: Mutex<HashMap<EndpointId, SyncSender<MailboxMessage>>>,
    next_id: AtomicU64,
}

#[derive(Clone)]
pub struct LocalMailboxHub {
    inner: Arc<Inner>,
    capacity: usize,
}

impl LocalMailboxHub {
    pub fn new(capacity: usize) -> Result<Self, MailboxError> {
        if !(1..=MAX_QUEUE_CAPACITY).contains(&capacity) {
            return Err(MailboxError::InvalidCapacity);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                mailboxes: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
            }),
            capacity,
        })
    }

    pub fn connect(&self) -> Result<MailboxEndpoint, MailboxError> {
        let raw = self.inner.next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| MailboxError::IdExhausted)?;
        let id = EndpointId(raw);
        let (tx, rx) = sync_channel(self.capacity);
        self.inner.mailboxes.lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, tx);
        Ok(MailboxEndpoint { id, inner: Arc::clone(&self.inner), inbox: rx })
    }
}

pub struct MailboxEndpoint {
    id: EndpointId,
    inner: Arc<Inner>,
    inbox: Receiver<MailboxMessage>,
}

impl MailboxEndpoint {
    pub fn id(&self) -> EndpointId { self.id }

    pub fn send(&self, to: EndpointId, correlation_id: u64, bytes: Vec<u8>) -> Result<(), MailboxError> {
        if bytes.len() > MAX_MESSAGE_BYTES { return Err(MailboxError::TooLarge); }
        let mailboxes = self.inner.mailboxes.lock().unwrap_or_else(|p| p.into_inner());
        let tx = mailboxes.get(&to).ok_or(MailboxError::PeerUnavailable)?;
        tx.try_send(MailboxMessage { from: self.id, correlation_id, bytes }).map_err(|e| match e {
            TrySendError::Full(_) => MailboxError::Full,
            TrySendError::Disconnected(_) => MailboxError::PeerUnavailable,
        })
    }

    pub fn receive(&self, timeout: Duration) -> Result<MailboxMessage, MailboxError> {
        self.inbox.recv_timeout(timeout).map_err(|e| match e {
            RecvTimeoutError::Timeout => MailboxError::Timeout,
            RecvTimeoutError::Disconnected => MailboxError::Closed,
        })
    }
}

impl Drop for MailboxEndpoint {
    fn drop(&mut self) {
        self.inner.mailboxes.lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn endpoints_exchange_opaque_binary_messages() {
        let hub = LocalMailboxHub::new(4).unwrap();
        let left = hub.connect().unwrap();
        let right = hub.connect().unwrap();
        let right_id = right.id();
        let worker = thread::spawn(move || {
            for _ in 0..3 {
                let m = right.receive(Duration::from_secs(1)).unwrap();
                right.send(m.from, m.correlation_id, m.bytes).unwrap();
            }
        });
        for (i, payload) in [vec![0, 255, 1], (0..=255).collect(), b"hello".to_vec()].iter().enumerate() {
            left.send(right_id, i as u64, payload.clone()).unwrap();
            let reply = left.receive(Duration::from_secs(1)).unwrap();
            assert_eq!(reply.from, right_id);
            assert_eq!(reply.correlation_id, i as u64);
            assert_eq!(&reply.bytes, payload);
        }
        worker.join().unwrap();
    }

    #[test]
    fn queue_backpressure_and_missing_peers_are_explicit() {
        let hub = LocalMailboxHub::new(1).unwrap();
        let sender = hub.connect().unwrap();
        let receiver = hub.connect().unwrap();
        let target = receiver.id();
        sender.send(target, 1, vec![1]).unwrap();
        assert_eq!(sender.send(target, 2, vec![2]), Err(MailboxError::Full));
        drop(receiver);
        assert_eq!(sender.send(target, 3, vec![3]), Err(MailboxError::PeerUnavailable));
    }

    #[test]
    fn capacity_and_payload_size_are_bounded() {
        assert_eq!(LocalMailboxHub::new(0).err(), Some(MailboxError::InvalidCapacity));
        let hub = LocalMailboxHub::new(1).unwrap();
        let sender = hub.connect().unwrap();
        let receiver = hub.connect().unwrap();
        assert_eq!(
            sender.send(receiver.id(), 1, vec![0; MAX_MESSAGE_BYTES + 1]),
            Err(MailboxError::TooLarge)
        );
    }
}
