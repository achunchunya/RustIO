//! AWS chunked transfer encoding 解码器 + 链式 SigV4 验签
//!
//! 实现 MinIO `s3ChunkedReader` 等价功能：解析 aws-chunked 块帧、逐块验证 chunk-signature
//! 链式签名（每块依赖上一块签名，初始为 seed），解帧后的明文流式产出，内存恒定。
//!
//! 支持四种 payload 声明：
//! - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`：签名块，无 trailer
//! - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`：签名块 + trailer（含 x-amz-trailer-signature）
//! - `STREAMING-UNSIGNED-PAYLOAD-TRAILER`：无签名块 + trailer（新版 AWS SDK 默认 CRC32 走此路径）
//!
//! 块格式：`<hex-size>[;chunk-signature=<sig>]\r\n<payload>\r\n`，末尾 0 块结束；
//! trailer 模式下 0 块后跟 `name:value\r\n` 行，空行或 EOF 终止。
//! 参考：https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 签名验证状态（unsigned chunked 时为 None）。
struct ChunkSigningState {
    /// 上一块签名（初始为 seed signature，逐块更新为当前块签名）
    prev_signature: String,
    signing_key: Vec<u8>,
    amz_date: String,
    credential_scope: String,
}

/// aws-chunked 解码器（边读边解帧 + 可选链式验签 + 可选 trailer 解析）。
pub(crate) struct AwsChunkedDecoder<R> {
    inner: R,
    signing: Option<ChunkSigningState>,
    /// 是否在 0 块后解析 trailer 行（STREAMING-*-TRAILER）
    expect_trailer: bool,
    /// 解析出的 trailer 头（小写 name → 原始 value），decode 完成后供调用方读取
    trailers: Vec<(String, String)>,
    /// 行缓冲（解析块头用，复用避免频繁分配）
    line_buf: Vec<u8>,
}

impl<R: tokio::io::AsyncRead + Unpin> AwsChunkedDecoder<R> {
    /// 构造解码器：`ctx=None` 表示 unsigned chunked（块头无 chunk-signature），
    /// `expect_trailer` 表示 0 块后有 trailer 行需解析。
    pub(crate) fn with_options(
        inner: R,
        ctx: Option<crate::routes::s3_sign::StreamingSigV4Context>,
        expect_trailer: bool,
    ) -> Self {
        Self {
            inner,
            signing: ctx.map(|ctx| ChunkSigningState {
                prev_signature: ctx.seed_signature,
                signing_key: ctx.signing_key,
                amz_date: ctx.amz_date,
                credential_scope: ctx.credential_scope,
            }),
            expect_trailer,
            trailers: Vec::new(),
            line_buf: Vec::with_capacity(256),
        }
    }

    /// decode 完成后取 trailer 头（小写 name → value）。
    pub(crate) fn trailers(&self) -> &[(String, String)] {
        &self.trailers
    }

    /// 解码整个流（逐块解帧 + 验签），返回明文数据。
    ///
    /// 内部累积到 Vec——part 上传通常几十到几百 MB，内存可控。后续可优化为流式写文件边验签。
    pub(crate) async fn decode_all(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let mut result = Vec::new();
        loop {
            let (chunk_size, chunk_sig) = self.parse_chunk_header().await?;

            if chunk_size == 0 {
                self.finish_stream(chunk_sig).await?;
                break;
            }

            // 读取块数据
            let mut chunk_data = vec![0u8; chunk_size];
            self.inner.read_exact(&mut chunk_data).await?;

            // 读块尾 \r\n
            let mut trailing = [0u8; 2];
            self.inner.read_exact(&mut trailing).await?;
            if &trailing != b"\r\n" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing \\r\\n after chunk data",
                ));
            }

            // 验签（unsigned chunked 时跳过）
            self.verify_chunk_signature(&chunk_data, chunk_sig.as_deref())?;
            result.extend_from_slice(&chunk_data);
        }

        Ok(result)
    }

    /// 流式解码（逐块解帧 + 链式验签），边解码边写入 `writer` 并喂增量 `etag`，返回明文总字节数。
    ///
    /// 与 `decode_all` 的区别：明文不累积到内存，对大对象（单次 PUT aws-chunked）内存恒定。
    /// 块签名链式（`verify_chunk_signature`）已保证完整性，无需额外 sha256 比对。
    /// 调用方需保证 `self.inner` 是真正的流式 `AsyncRead`（如 `StreamReader`），否则失去省内存意义。
    pub(crate) async fn decode_into<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        etag: &mut WeakEtagHasher,
        mut checksum: Option<&mut crate::routes::s3_checksum::ChecksumHasher>,
    ) -> Result<u64, std::io::Error> {
        let mut total: u64 = 0;
        loop {
            let (chunk_size, chunk_sig) = self.parse_chunk_header().await?;

            if chunk_size == 0 {
                self.finish_stream(chunk_sig).await?;
                break;
            }

            // 读取块数据
            let mut chunk_data = vec![0u8; chunk_size];
            self.inner.read_exact(&mut chunk_data).await?;

            // 读块尾 \r\n
            let mut trailing = [0u8; 2];
            self.inner.read_exact(&mut trailing).await?;
            if &trailing != b"\r\n" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing \\r\\n after chunk data",
                ));
            }

            // 验签（unsigned chunked 时跳过），通过后流式产出明文
            self.verify_chunk_signature(&chunk_data, chunk_sig.as_deref())?;
            writer.write_all(&chunk_data).await?;
            etag.update(&chunk_data);
            if let Some(hasher) = checksum.as_deref_mut() {
                hasher.update(&chunk_data);
            }
            total += chunk_data.len() as u64;
        }

        Ok(total)
    }

    /// 0 块收尾：验证 0 块签名（签名流），随后按模式解析 trailer 行或读末尾 \r\n。
    async fn finish_stream(&mut self, chunk_sig: Option<String>) -> Result<(), std::io::Error> {
        self.verify_chunk_signature(&[], chunk_sig.as_deref())?;

        if !self.expect_trailer {
            let mut trailing = [0u8; 2];
            self.inner.read_exact(&mut trailing).await?;
            if &trailing != b"\r\n" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing \\r\\n after 0-chunk",
                ));
            }
            return Ok(());
        }

        // trailer 模式：读 `name:value\r\n` 行直到空行或 EOF
        let mut trailer_signature: Option<String> = None;
        loop {
            let Some(line) = self.read_line_eof_ok().await? else {
                break;
            };
            if line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed trailer line (missing ':')",
                ));
            };
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "x-amz-trailer-signature" {
                trailer_signature = Some(value);
            } else {
                self.trailers.push((name, value));
            }
        }

        // 签名流的 trailer 必须带 x-amz-trailer-signature 且验证通过
        if let Some(signing) = &self.signing {
            let Some(client_sig) = trailer_signature else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing x-amz-trailer-signature",
                ));
            };
            let mut trailer_block = String::new();
            for (name, value) in &self.trailers {
                trailer_block.push_str(name);
                trailer_block.push(':');
                trailer_block.push_str(value);
                trailer_block.push('\n');
            }
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
                signing.amz_date,
                signing.credential_scope,
                signing.prev_signature,
                sha256_hex(trailer_block.as_bytes()),
            );
            let computed = hmac_sha256_hex(&signing.signing_key, &string_to_sign);
            if !computed.eq_ignore_ascii_case(&client_sig) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "trailer signature does not match",
                ));
            }
        }
        Ok(())
    }

    /// 读一行（去掉 \r\n）；行首即 EOF 时返回 None（trailer 末尾允许无空行直接结束）。
    async fn read_line_eof_ok(&mut self) -> Result<Option<String>, std::io::Error> {
        self.line_buf.clear();
        loop {
            let byte = match self.inner.read_u8().await {
                Ok(byte) => byte,
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    if self.line_buf.is_empty() {
                        return Ok(None);
                    }
                    return Err(err);
                }
                Err(err) => return Err(err),
            };
            self.line_buf.push(byte);
            if self.line_buf.ends_with(b"\r\n") {
                break;
            }
            if self.line_buf.len() > 4096 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "trailer line exceeds 4096 bytes",
                ));
            }
        }
        let line = std::str::from_utf8(&self.line_buf[..self.line_buf.len() - 2])
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid UTF-8 in trailer")
            })?
            .to_string();
        Ok(Some(line))
    }

    /// 解析块头：`<hex-size>[;chunk-signature=<sig>]\r\n`，返回 (chunk_size, signature)。
    ///
    /// 签名流要求带 chunk-signature，unsigned 流块头只有 hex 大小。
    /// 对齐 MinIO：块大小上限 16 MiB，超过拒绝（防 DoS）。
    async fn parse_chunk_header(&mut self) -> Result<(usize, Option<String>), std::io::Error> {
        self.line_buf.clear();
        loop {
            let byte = self.inner.read_u8().await?;
            self.line_buf.push(byte);
            if self.line_buf.ends_with(b"\r\n") {
                break;
            }
            if self.line_buf.len() > 512 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "chunk header exceeds 512 bytes",
                ));
            }
        }

        let line =
            std::str::from_utf8(&self.line_buf[..self.line_buf.len() - 2]).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid UTF-8 in chunk header",
                )
            })?;

        // 解析 `<hex>[;chunk-signature=<sig>]`
        let (size_hex, sig) = match line.split_once(';') {
            Some((size_hex, rest)) => {
                let Some(sig) = rest.strip_prefix("chunk-signature=") else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "missing 'chunk-signature=' in chunk header",
                    ));
                };
                (size_hex, Some(sig.to_string()))
            }
            None => (line, None),
        };
        if self.signing.is_some() && sig.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing ';chunk-signature=' in signed chunk header",
            ));
        }
        let chunk_size = usize::from_str_radix(size_hex, 16).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex chunk size")
        })?;

        if chunk_size > 16 * 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunk size exceeds 16 MiB limit",
            ));
        }

        Ok((chunk_size, sig))
    }

    /// 验证块签名（链式：string_to_sign 含上一块签名 + 当前块 hash）；unsigned 流为 no-op。
    fn verify_chunk_signature(
        &mut self,
        chunk_data: &[u8],
        client_sig: Option<&str>,
    ) -> Result<(), std::io::Error> {
        let Some(signing) = &mut self.signing else {
            return Ok(());
        };
        let Some(client_sig) = client_sig else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing chunk signature",
            ));
        };
        // AWS4-HMAC-SHA256-PAYLOAD 签名算法：
        // string_to_sign = "AWS4-HMAC-SHA256-PAYLOAD\n{date}\n{scope}\n{prev_sig}\n{empty_sha256}\n{chunk_sha256}"
        let chunk_hash = sha256_hex(chunk_data);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            signing.amz_date,
            signing.credential_scope,
            signing.prev_signature,
            EMPTY_SHA256,
            chunk_hash
        );

        let computed_sig = hmac_sha256_hex(&signing.signing_key, &string_to_sign);
        if !computed_sig.eq_ignore_ascii_case(client_sig) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "chunk signature does not match",
            ));
        }
        signing.prev_signature = client_sig.to_string();
        Ok(())
    }
}

/// MD5 增量 hasher（用于单次 PUT 流式计算 S3 ETag）。
pub(crate) struct WeakEtagHasher {
    hasher: md5::Md5,
}

impl WeakEtagHasher {
    pub(crate) fn new() -> Self {
        Self {
            hasher: md5::Md5::new(),
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    pub(crate) fn finalize(self) -> String {
        let result = self.hasher.finalize();
        format!("{:x}", result)
    }
}

