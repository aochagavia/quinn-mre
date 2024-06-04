use std::time::Duration;
use quinn_proto::{ConnectionId, ConnectionIdGenerator};

pub struct NoConnectionIdGenerator;

impl ConnectionIdGenerator for NoConnectionIdGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        ConnectionId::new(&[])
    }

    fn cid_len(&self) -> usize {
        0
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}
