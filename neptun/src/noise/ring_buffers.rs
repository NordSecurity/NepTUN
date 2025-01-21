use super::Endpoint;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::sync::{atomic::AtomicBool, Arc};
const UDP_SIZE: usize = (1 << 12) - 1;

pub const RB_SIZE: usize = 20;

pub struct RingBuffer<T> {
    pub ring_buffer: Vec<T>,
    iter: Mutex<usize>,
}

impl<T> RingBuffer<T> {
    // Returns the next element in ring buffer
    // and moves the ring buffer iterator forward
    pub fn get_next(&mut self) -> &mut T {
        let mut idx = self.iter.lock();
        if *idx == RB_SIZE {
            // Reset the write iterator
            *idx = 0;
        }
        let element = &mut self.ring_buffer[*idx];
        *idx += 1;
        element
    }
}

pub struct EncryptionTaskData {
    pub data: [u8; UDP_SIZE],
    pub buf_len: usize,
    pub endpoint: Arc<parking_lot::RwLock<Endpoint>>,
    pub is_element_free: AtomicBool,
}

pub static mut TX_RING_BUFFER: Lazy<RingBuffer<EncryptionTaskData>> = Lazy::new(|| {
    let mut deque = Vec::with_capacity(RB_SIZE);
    for _ in 0..RB_SIZE {
        deque.push(EncryptionTaskData {
            data: [0; UDP_SIZE],
            buf_len: 0,
            endpoint: Arc::default(),
            is_element_free: AtomicBool::new(true),
        });
    }
    RingBuffer {
        ring_buffer: deque,
        iter: Mutex::new(0),
    }
});
