//! 登录速率限制:基于 (源IP, 用户名) 的失败计数与渐进冷却。
//!
//! 默认策略:连续 5 次失败后，权重递增延迟(5s→30s→5min→30min)；
//! 首次成功后重置计数。全内存实现，重启丢失(可接受——防暴力破解非防 APT)。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 每对 (IP, username) 的失败状态。
#[derive(Debug, Clone)]
struct AttemptRecord {
    failures: u32,
    cooldown_until: Option<Instant>,
    last_attempt: Instant,
}

/// 登录速率限制器(线程安全)。
pub(crate) struct LoginRateLimiter {
    inner: Mutex<HashMap<(String, String), AttemptRecord>>,
    max_failures: u32,
    /// 冷却阶梯:索引 0 是第 1 次超额后的延迟,以此类推。
    cooldown_steps: Vec<Duration>,
}

impl LoginRateLimiter {
    pub fn new(max_failures: u32, cooldown_steps: Vec<Duration>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_failures,
            cooldown_steps,
        }
    }

    /// 默认策略:5 次失败后依次冷却 5s / 30s / 5min / 30min。
    pub fn default_policy() -> Self {
        Self::new(
            5,
            vec![
                Duration::from_secs(5),
                Duration::from_secs(30),
                Duration::from_secs(300),
                Duration::from_secs(1800),
            ],
        )
    }

    /// 尝试登录前调用。返回 Ok 表示允许尝试；Err 返回需等待的秒数上限。
    pub fn check(&self, ip: &str, username: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.purge_expired(&mut map, now);

        let key = (ip.to_lowercase(), username.to_lowercase());
        if let Some(record) = map.get(&key) {
            if let Some(cooldown) = record.cooldown_until {
                if now <= cooldown {
                    let remain = cooldown.duration_since(now).as_secs().max(1);
                    return Err(remain);
                }
            }
        }
        Ok(())
    }

    /// 登录失败后调用，递增计数并可能进入冷却。
    pub fn record_failure(&self, ip: &str, username: &str) {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (ip.to_lowercase(), username.to_lowercase());
        let record = map.entry(key).or_insert(AttemptRecord {
            failures: 0,
            cooldown_until: None,
            last_attempt: now,
        });
        record.failures += 1;
        record.last_attempt = now;

        if record.failures >= self.max_failures {
            let over = record.failures - self.max_failures;
            let step_idx = (over as usize).min(self.cooldown_steps.len() - 1);
            record.cooldown_until = Some(now + self.cooldown_steps[step_idx]);
        }
    }

    /// 登录成功后调用，重置该用户计数。
    pub fn record_success(&self, ip: &str, username: &str) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (ip.to_lowercase(), username.to_lowercase());
        map.remove(&key);
    }

    /// 清理超过 1 小时无活动且不在冷却中的记录。
    fn purge_expired(&self, map: &mut HashMap<(String, String), AttemptRecord>, now: Instant) {
        let cutoff = now - Duration::from_secs(3600);
        map.retain(|_, record| {
            record.cooldown_until.is_some_and(|c| c > now) || record.last_attempt > cutoff
        });
    }
}

