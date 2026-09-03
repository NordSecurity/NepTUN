use std::sync::Arc;

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
use std::thread::{self, JoinHandle};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
use dispatch2::{DispatchGroup, DispatchQueue, DispatchQueueAttr, DispatchRetained, DispatchTime};

use crate::device::{
    dev_lock::Lock, tun::TunSocket, Device, DeviceHandle, ThreadData, MAX_PKT_SIZE,
};

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
type ControlThread = JoinHandle<()>;
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
type ControlThread = DispatchRetained<DispatchGroup>;

pub struct Control {
    pub thread: ControlThread,
}

impl Control {
    pub fn start(device: Arc<Lock<Device>>) -> (Self, Arc<Lock<Vec<Arc<TunSocket>>>>) {
        let sockets = Arc::new(Lock::new(vec![]));
        let thread_data = {
            let d = &device.read();
            ThreadData {
                src_buf: [0u8; MAX_PKT_SIZE],
                dst_buf: [0u8; MAX_PKT_SIZE],
                iface: Arc::clone(&d.iface),
                update_seq: d.update_seq,
            }
        };

        sockets
            .read()
            .try_writeable(|_| {}, |fds| fds.push(thread_data.iface.clone()));

        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        let thread = {
            let group = DispatchGroup::new();
            let queue = DispatchQueue::new("neptun-control", DispatchQueueAttr::SERIAL);
            // TODO: ensure P-core preference for execution
            group.exec_async(&queue, move || Control::event_loop(thread_data, &device));
            group
        };

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        let thread = {
            thread::Builder::new()
                .name("neptun-control".to_string())
                .spawn(move || Control::event_loop(thread_data, &device))
                .unwrap()
        };

        (Self { thread }, sockets)
    }

    /// Responsible for handling:
    /// - handshake / cookie
    /// - timers - rekey - keepalive
    /// - peer config
    /// - socket lifecycle
    fn event_loop(thread_data: ThreadData, device: &Lock<Device>) {
        DeviceHandle::event_loop(thread_data, device);
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    pub(crate) fn join(self) {
        if let Err(e) = self.thread.join() {
            tracing::error!(message = "Unable to gracefully clode outbound thread.", error = ?e);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    pub(crate) fn join(self) {
        let _ = self.thread.wait(DispatchTime::FOREVER);
    }
}
