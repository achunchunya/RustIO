//! io_uring 线程桥接：专用线程跑 tokio-uring，通过 mpsc channel 桥接到标准 tokio runtime。
//!
//! Linux 5.10+ 且启用 `io-uring` feature 时生效；其余平台回退到 tokio::fs（spawn_blocking）。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// I/O 请求类型。
enum IoRequest {
    Write {
        path: PathBuf,
        offset: u64,
        data: Vec<u8>,
        resp: oneshot::Sender<Result<(), String>>,
    },
    #[allow(dead_code)]
    Read {
        path: PathBuf,
        offset: u64,
        len: usize,
        resp: oneshot::Sender<Result<Vec<u8>, String>>,
    },
}

/// io_uring 线程桥接器。
///
/// 内部维护 N 个专用线程，每个线程内跑 tokio-uring runtime。
/// 外部通过 `write_file` / `read_file` 发送 I/O 请求，由专用线程执行。
pub(crate) struct IoUringBridge {
    tx: mpsc::Sender<IoRequest>,
}

impl IoUringBridge {
    /// 创建桥接器，启动 `num_workers` 个专用 I/O 线程。
    pub(crate) fn new(num_workers: usize) -> Self {
        let (tx, rx) = mpsc::channel::<IoRequest>(256);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));

        for _ in 0..num_workers.max(1) {
            let rx = rx.clone();
            std::thread::Builder::new()
                .name("io-uring-worker".to_string())
                .spawn(move || {
                    Self::worker_loop(rx);
                })
                .expect("failed to spawn io_uring worker thread");
        }
        Self { tx }
    }

    /// 写文件：将 `data` 写入 `path` 的 `offset` 位置。
    pub(crate) async fn write_file(
        &self,
        path: &Path,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<(), String> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(IoRequest::Write {
                path: path.to_path_buf(),
                offset,
                data,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "io_uring bridge channel closed".to_string())?;
        resp_rx
            .await
            .map_err(|_| "io_uring bridge response dropped".to_string())?
    }

    /// 读文件：从 `path` 的 `offset` 位置读取 `len` 字节。
    #[allow(dead_code)]
    pub(crate) async fn read_file(
        &self,
        path: &Path,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, String> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(IoRequest::Read {
                path: path.to_path_buf(),
                offset,
                len,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "io_uring bridge channel closed".to_string())?;
        resp_rx
            .await
            .map_err(|_| "io_uring bridge response dropped".to_string())?
    }
}

// ── Linux + io-uring feature: 使用 tokio-uring ──

#[cfg(all(target_os = "linux", feature = "io-uring"))]
impl IoUringBridge {
    fn worker_loop(rx: Arc<tokio::sync::Mutex<mpsc::Receiver<IoRequest>>>) {
        tokio_uring::start(async move {
            loop {
                let req = {
                    let mut guard = rx.lock().await;
                    match guard.recv().await {
                        Some(r) => r,
                        None => break,
                    }
                };
                match req {
                    IoRequest::Write { path, offset, data, resp } => {
                        let result = async {
                            let file = tokio_uring::fs::OpenOptions::new()
                                .write(true)
                                .create(true)
                                .open(&path)
                                .await
                                .map_err(|e| format!("open for write: {e}"))?;
                            file.write_all_at(data, offset)
                                .await
                                .0
                                .map_err(|e| format!("write: {e}"))?;
                            file.close().await.map_err(|e| format!("close: {e}"))?;
                            Ok::<(), String>(())
                        }
                        .await;
                        let _ = resp.send(result);
                    }
                    IoRequest::Read { path, offset, len, resp } => {
                        let result = async {
                            let file = tokio_uring::fs::OpenOptions::new()
                                .read(true)
                                .open(&path)
                                .await
                                .map_err(|e| format!("open for read: {e}"))?;
                            let buf = vec![0u8; len];
                            let (res, buf) = file.read_at(buf, offset).await;
                            let n = res.map_err(|e| format!("read: {e}"))?;
                            file.close().await.map_err(|e| format!("close: {e}"))?;
                            Ok(buf[..n].to_vec())
                        }
                        .await;
                        let _ = resp.send(result);
                    }
                }
            }
        });
    }
}

// ── 非 Linux 或未启用 io-uring feature: 回退到标准 tokio::fs ──

#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
impl IoUringBridge {
    fn worker_loop(rx: Arc<tokio::sync::Mutex<mpsc::Receiver<IoRequest>>>) {
        // 每个 worker 线程启动一个 tokio runtime 处理 I/O 请求
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build fallback tokio runtime for io_uring bridge");
        rt.block_on(async move {
            loop {
                let req = {
                    let mut guard = rx.lock().await;
                    match guard.recv().await {
                        Some(r) => r,
                        None => break,
                    }
                };
                match req {
                    IoRequest::Write { path, offset, data, resp } => {
                        let result = async {
                            use tokio::io::AsyncWriteExt;
                            let mut file = tokio::fs::OpenOptions::new()
                                .write(true)
                                .create(true)
                                .truncate(offset == 0)
                                .open(&path)
                                .await
                                .map_err(|e| format!("open for write: {e}"))?;
                            if offset > 0 {
                                use tokio::io::AsyncSeekExt;
                                file.seek(std::io::SeekFrom::Start(offset))
                                    .await
                                    .map_err(|e| format!("seek: {e}"))?;
                            }
                            file.write_all(&data)
                                .await
                                .map_err(|e| format!("write: {e}"))?;
                            file.flush().await.map_err(|e| format!("flush: {e}"))?;
                            Ok::<(), String>(())
                        }
                        .await;
                        let _ = resp.send(result);
                    }
                    IoRequest::Read { path, offset, len, resp } => {
                        let result = async {
                            use tokio::io::{AsyncReadExt, AsyncSeekExt};
                            let mut file = tokio::fs::File::open(&path)
                                .await
                                .map_err(|e| format!("open for read: {e}"))?;
                            if offset > 0 {
                                file.seek(std::io::SeekFrom::Start(offset))
                                    .await
                                    .map_err(|e| format!("seek: {e}"))?;
                            }
                            let mut buf = vec![0u8; len];
                            let n = file
                                .read(&mut buf)
                                .await
                                .map_err(|e| format!("read: {e}"))?;
                            buf.truncate(n);
                            Ok::<Vec<u8>, String>(buf)
                        }
                        .await;
                        let _ = resp.send(result);
                    }
                }
            }
        });
    }
}

/// 检测当前 Linux 内核版本是否支持 io_uring (≥ 5.10)。
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub(crate) fn is_io_uring_available() -> bool {
    match std::fs::read_to_string("/proc/version") {
        Ok(version) => {
            // 解析 "Linux version X.Y.Z-..." 中的主版本号
            let parts: Vec<&str> = version.split_whitespace().collect();
            if parts.len() >= 3 {
                let ver = parts[2];
                let mut nums = ver.splitn(3, '.');
                if let (Some(major), Some(minor)) = (nums.next(), nums.next()) {
                    if let (Ok(maj), Ok(min)) = (major.parse::<u32>(), minor.parse::<u32>()) {
                        return (maj, min) >= (5, 10);
                    }
                }
            }
            false
        }
        Err(_) => false,
    }
}

#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
pub(crate) fn is_io_uring_available() -> bool {
    false
}
