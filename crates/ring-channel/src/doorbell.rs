/// Cross-platform doorbell: eventfd on Linux, channel-based on other platforms.
pub struct Doorbell {
    inner: DoorbellInner,
}

enum DoorbellInner {
    #[cfg(target_os = "linux")]
    EventFd(i32),
    Channel {
        tx: std::sync::Mutex<std::sync::mpsc::SyncSender<()>>,
        rx: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    },
}

impl Doorbell {
    pub fn new() -> Result<Self, std::io::Error> {
        #[cfg(target_os = "linux")]
        {
            let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_SEMAPHORE) };
            if fd >= 0 {
                return Ok(Self { inner: DoorbellInner::EventFd(fd) });
            }
        }

        let (tx, rx) = std::sync::mpsc::sync_channel(64);
        Ok(Self {
            inner: DoorbellInner::Channel {
                tx: std::sync::Mutex::new(tx),
                rx: std::sync::Mutex::new(rx),
            },
        })
    }

    /// Signals the consumer that new data is available.
    pub fn ring(&self) {
        match &self.inner {
            #[cfg(target_os = "linux")]
            DoorbellInner::EventFd(fd) => {
                let val: u64 = 1;
                unsafe { libc::write(*fd, &val as *const _ as *const libc::c_void, 8); }
            }
            DoorbellInner::Channel { tx, .. } => {
                if let Ok(guard) = tx.lock() {
                    let _ = guard.try_send(());
                }
            }
        }
    }

    /// Drains one notification. Called by the consumer after waking.
    pub fn consume(&self) {
        match &self.inner {
            #[cfg(target_os = "linux")]
            DoorbellInner::EventFd(fd) => {
                let mut buf = [0u8; 8];
                unsafe { libc::read(*fd, buf.as_mut_ptr() as *mut libc::c_void, 8); }
            }
            DoorbellInner::Channel { rx, .. } => {
                if let Ok(guard) = rx.lock() {
                    let _ = guard.try_recv();
                }
            }
        }
    }

    /// Raw fd for async monitoring (Linux only; returns -1 on other platforms).
    pub fn raw_fd(&self) -> i32 {
        match &self.inner {
            #[cfg(target_os = "linux")]
            DoorbellInner::EventFd(fd) => *fd,
            _ => -1,
        }
    }

    /// Async wait: parks until data arrives.
    pub async fn wait(&self) {
        match &self.inner {
            #[cfg(target_os = "linux")]
            DoorbellInner::EventFd(fd) => {
                use tokio::io::unix::AsyncFd;
                if let Ok(afd) = AsyncFd::new(*fd) {
                    let _ = afd.readable().await;
                }
            }
            DoorbellInner::Channel { .. } => {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
    }
}

impl Drop for Doorbell {
    fn drop(&mut self) {
        match &self.inner {
            #[cfg(target_os = "linux")]
            DoorbellInner::EventFd(fd) => {
                unsafe { libc::close(*fd); }
            }
            _ => {}
        }
    }
}

unsafe impl Send for Doorbell {}
unsafe impl Sync for Doorbell {}
