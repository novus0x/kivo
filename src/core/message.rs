use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_MSG_ID: AtomicU64 = AtomicU64::new(1);

pub struct Message {
    pub id: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub content: String,
    pub timestamp: u64,
}

impl Message {
    pub fn new(sender_id: &str, recipient_id: &str, content: &str) -> Self {
        let seq = NEXT_MSG_ID.fetch_add(1, Ordering::Relaxed);
        Message {
            id: format!("msg-{seq}"),
            sender_id: sender_id.to_string(),
            recipient_id: recipient_id.to_string(),
            content: content.to_string(),
            timestamp: 0,
        }
    }
}
