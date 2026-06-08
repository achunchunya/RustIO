use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// PHC 字符串前缀,用于区分已哈希凭据与历史明文凭据。
const PHC_PREFIX: &str = "$argon2";

/// 用 Argon2id 对明文密码生成带随机盐的 PHC 哈希串。
pub(crate) fn hash_password(plain: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| format!("密码哈希失败 / failed to hash password: {err}"))
}

/// 判断存储值是否已是 Argon2 PHC 哈希(用于兼容历史明文凭据的渐进迁移)。
pub(crate) fn is_hashed(stored: &str) -> bool {
    stored.starts_with(PHC_PREFIX)
}

/// 校验明文密码:存储值为 PHC 哈希则走 Argon2 验签(恒定时间),
/// 否则按历史明文凭据恒定时间比较(兼容旧数据,登录成功后由上层重新哈希)。
pub(crate) fn verify_password(plain: &str, stored: &str) -> bool {
    if is_hashed(stored) {
        match PasswordHash::new(stored) {
            Ok(parsed) => Argon2::default()
                .verify_password(plain.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        }
    } else {
        constant_time_eq(plain.as_bytes(), stored.as_bytes())
    }
}

/// 恒定时间字节比较,避免明文/令牌比较的时序侧信道。
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

