//! S3 Checksum（x-amz-checksum-*）算法与请求/响应处理
//!
//! 支持 CRC32 / CRC32C / SHA1 / SHA256 / CRC64NVME 五种算法，
//! FULL_OBJECT 与 COMPOSITE（checksum-of-checksums）两种 multipart 合成方式。
//! 参考：https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html

use super::*;
use base64::Engine;
use sha1::Sha1;

/// S3 支持的 checksum 算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChecksumAlgorithm {
    Crc32,
    Crc32c,
    Sha1,
    Sha256,
    Crc64Nvme,
}

impl ChecksumAlgorithm {
    /// 解析算法名（大小写不敏感，如 `CRC32C`、`sha256`）。
    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_uppercase().as_str() {
            "CRC32" => Some(Self::Crc32),
            "CRC32C" => Some(Self::Crc32c),
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "CRC64NVME" => Some(Self::Crc64Nvme),
            _ => None,
        }
    }

    /// 规范算法名（用于元数据存储与响应头后缀）。
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Crc32 => "CRC32",
            Self::Crc32c => "CRC32C",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Crc64Nvme => "CRC64NVME",
        }
    }

    /// 对应请求/响应头名（小写）。
    pub(crate) fn header_name(&self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
        }
    }

    /// 全部算法（按 AWS 文档顺序）。
    pub(crate) fn all() -> [Self; 5] {
        [
            Self::Crc32,
            Self::Crc32c,
            Self::Sha1,
            Self::Sha256,
            Self::Crc64Nvme,
        ]
    }

    /// CompleteMultipartUpload 请求 XML 中的 Part 子标签名。
    pub(crate) fn xml_tag(&self) -> &'static str {
        match self {
            Self::Crc32 => "ChecksumCRC32",
            Self::Crc32c => "ChecksumCRC32C",
            Self::Sha1 => "ChecksumSHA1",
            Self::Sha256 => "ChecksumSHA256",
            Self::Crc64Nvme => "ChecksumCRC64NVME",
        }
    }

    /// 是否支持 COMPOSITE 合成（AWS 规定 CRC64NVME 仅支持 FULL_OBJECT）。
    pub(crate) fn supports_composite(&self) -> bool {
        !matches!(self, Self::Crc64Nvme)
    }

    pub(crate) fn hasher(&self) -> ChecksumHasher {
        match self {
            Self::Crc32 => ChecksumHasher::Crc32(crc32fast::Hasher::new()),
            Self::Crc32c => ChecksumHasher::Crc32c(0),
            Self::Sha1 => ChecksumHasher::Sha1(Sha1::new()),
            Self::Sha256 => ChecksumHasher::Sha256(Sha256::new()),
            Self::Crc64Nvme => ChecksumHasher::Crc64Nvme(crc64fast_nvme::Digest::new()),
        }
    }
}

/// 流式 checksum hasher（增量喂数据，finalize 输出 base64 值）。
pub(crate) enum ChecksumHasher {
    Crc32(crc32fast::Hasher),
    Crc32c(u32),
    Sha1(Sha1),
    Sha256(Sha256),
    Crc64Nvme(crc64fast_nvme::Digest),
}

impl ChecksumHasher {
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Crc32(hasher) => hasher.update(bytes),
            Self::Crc32c(state) => *state = crc32c::crc32c_append(*state, bytes),
            Self::Sha1(hasher) => hasher.update(bytes),
            Self::Sha256(hasher) => hasher.update(bytes),
            Self::Crc64Nvme(digest) => digest.write(bytes),
        }
    }

    /// 输出 base64 编码的 checksum 值（CRC 为大端字节序，与 AWS 一致）。
    pub(crate) fn finalize(self) -> String {
        match self {
            Self::Crc32(hasher) => BASE64.encode(hasher.finalize().to_be_bytes()),
            Self::Crc32c(state) => BASE64.encode(state.to_be_bytes()),
            Self::Sha1(hasher) => BASE64.encode(hasher.finalize()),
            Self::Sha256(hasher) => BASE64.encode(hasher.finalize()),
            Self::Crc64Nvme(digest) => BASE64.encode(digest.sum64().to_be_bytes()),
        }
    }
}

/// 一次性计算 checksum（小数据场景）。
pub(crate) fn compute_checksum(algorithm: ChecksumAlgorithm, bytes: &[u8]) -> String {
    let mut hasher = algorithm.hasher();
    hasher.update(bytes);
    hasher.finalize()
}

/// 从请求头解析的 checksum 要求。
#[derive(Debug, Clone)]
pub(crate) struct ChecksumRequest {
    pub(crate) algorithm: ChecksumAlgorithm,
    /// 请求头里携带的期望值（base64）；trailing checksum 场景为 None，由 trailer 提供
    pub(crate) expected: Option<String>,
}

/// 解析 PutObject/UploadPart 请求头中的 checksum 要求。
///
/// 规则（对齐 AWS）：
/// - `x-amz-checksum-<alg>: <base64>` 直接携带期望值；多个算法头并存 → InvalidRequest
/// - `x-amz-sdk-checksum-algorithm: <ALG>` 声明算法；若同时有对应值头则二者须一致
/// - 仅声明算法无值头 → 值经 trailer 传递（trailing checksum），expected=None
pub(crate) fn parse_checksum_headers(
    headers: &HeaderMap,
) -> Result<Option<ChecksumRequest>, String> {
    let mut value_headers: Vec<(ChecksumAlgorithm, String)> = Vec::new();
    for algorithm in ChecksumAlgorithm::all() {
        if let Some(value) = headers
            .get(algorithm.header_name())
            .and_then(|value| value.to_str().ok())
        {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                value_headers.push((algorithm, trimmed.to_string()));
            }
        }
    }
    if value_headers.len() > 1 {
        return Err("Expecting a single x-amz-checksum- header".to_string());
    }

    let declared = headers
        .get("x-amz-sdk-checksum-algorithm")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            ChecksumAlgorithm::parse(value)
                .ok_or_else(|| format!("Unsupported checksum algorithm: {value}"))
        })
        .transpose()?;

    // `x-amz-trailer: x-amz-checksum-<alg>`：trailing checksum 模式下声明算法
    let trailer_declared = headers
        .get("x-amz-trailer")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .trim()
                .to_ascii_lowercase()
                .strip_prefix("x-amz-checksum-")
                .and_then(ChecksumAlgorithm::parse)
        });
    let declared = declared.or(trailer_declared);

    match (value_headers.pop(), declared) {
        (Some((algorithm, expected)), declared) => {
            if let Some(declared) = declared {
                if declared != algorithm {
                    return Err(
                        "x-amz-sdk-checksum-algorithm does not match x-amz-checksum- header"
                            .to_string(),
                    );
                }
            }
            Ok(Some(ChecksumRequest {
                algorithm,
                expected: Some(expected),
            }))
        }
        (None, Some(algorithm)) => Ok(Some(ChecksumRequest {
            algorithm,
            expected: None,
        })),
        (None, None) => Ok(None),
    }
}

/// 计算 COMPOSITE checksum：各 part checksum 的 base64 解码字节拼接后再做一次同算法
/// checksum，输出 `<base64>-<part 数>`。
pub(crate) fn compute_composite_checksum(
    algorithm: ChecksumAlgorithm,
    part_values: &[String],
) -> Result<String, String> {
    let mut concat = Vec::with_capacity(part_values.len() * 32);
    for value in part_values {
        let raw = BASE64
            .decode(value.trim())
            .map_err(|_| format!("Invalid base64 part checksum: {value}"))?;
        concat.extend_from_slice(&raw);
    }
    Ok(format!(
        "{}-{}",
        compute_checksum(algorithm, &concat),
        part_values.len()
    ))
}

/// 向响应追加 `x-amz-checksum-<alg>` 与 `x-amz-checksum-type` 头。
pub(crate) fn apply_checksum_headers(
    response: &mut Response,
    checksum: &rustio_core::types::S3ObjectChecksum,
) {
    let Some(algorithm) = ChecksumAlgorithm::parse(&checksum.algorithm) else {
        return;
    };
    if let Ok(value) = axum::http::HeaderValue::from_str(&checksum.value) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static(algorithm.header_name()),
            value,
        );
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(&checksum.checksum_type) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-checksum-type"),
            value,
        );
    }
}

/// GetObject/HeadObject 是否要求返回 checksum（`x-amz-checksum-mode: ENABLED`）。
pub(crate) fn checksum_mode_enabled(headers: &HeaderMap) -> bool {
    headers
        .get("x-amz-checksum-mode")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().eq_ignore_ascii_case("ENABLED"))
        .unwrap_or(false)
}

