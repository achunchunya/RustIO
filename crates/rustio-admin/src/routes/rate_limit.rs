//! 登录速率限制:基于 (源IP, 用户名) 的失败计数与渐进冷却 + 账户 lockout。
//!
//! 默认策略:连续 5 次失败后，权重递增延迟(5s→30s→5min→30min)；
//! 连续 10 次失败触发账户级 lockout(30 分钟，跨 IP 生效，管理员可解锁)。
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
    /// 账户级 lockout:连续失败超过此阈值后,该用户名全局 lockout。
    account_lockout_threshold: u32,
    /// 账户 lockout 持续时间。
    account_lockout_duration: Duration,
    /// 被 lockout 的用户名 → 解锁时间。
    locked_accounts: Mutex<HashMap<String, Instant>>,
}

impl LoginRateLimiter {
    pub fn new(max_failures: u32, cooldown_steps: Vec<Duration>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_failures,
            cooldown_steps,
            account_lockout_threshold: 10,
            account_lockout_duration: Duration::from_secs(1800),
            locked_accounts: Mutex::new(HashMap::new()),
        }
    }

    /// 默认策略:5 次失败后依次冷却 5s / 30s / 5min / 30min；10 次后账户 lockout 30 分钟。
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
    /// 先检查账户级 lockout,再检查 IP 级 cooldown。
    pub fn check(&self, ip: &str, username: &str) -> Result<(), u64> {
        let now = Instant::now();

        // 账户级 lockout(跨 IP 生效)
        {
            let mut locked = self.locked_accounts.lock().unwrap_or_else(|e| e.into_inner());
            // 清理过期 lockout
            locked.retain(|_, until| *until > now);
            if let Some(until) = locked.get(&username.to_lowercase()) {
                let remain = until.duration_since(now).as_secs().max(1);
                return Err(remain);
            }
        }

        // IP 级 cooldown
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

    /// 登录失败后调用，递增计数并可能进入冷却或触发账户 lockout。
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

        // 账户级 lockout:累计失败超过阈值,全局锁定该用户名
        if record.failures >= self.account_lockout_threshold {
            let mut locked = self.locked_accounts.lock().unwrap_or_else(|e| e.into_inner());
            locked.insert(
                username.to_lowercase(),
                now + self.account_lockout_duration,
            );
        }

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

    /// 管理员解锁被 lockout 的账户(供管理端点调用)。
    #[allow(dead_code)]
    pub fn unlock_account(&self, username: &str) {
        let mut locked = self.locked_accounts.lock().unwrap_or_else(|e| e.into_inner());
        locked.remove(&username.to_lowercase());
    }

    /// 查询账户是否被 lockout(供管理端点调用)。
    #[allow(dead_code)]
    pub fn is_account_locked(&self, username: &str) -> bool {
        let now = Instant::now();
        let mut locked = self.locked_accounts.lock().unwrap_or_else(|e| e.into_inner());
        locked.retain(|_, until| *until > now);
        locked.contains_key(&username.to_lowercase())
    }

    /// 清理超过 1 小时无活动且不在冷却中的记录。
    fn purge_expired(&self, map: &mut HashMap<(String, String), AttemptRecord>, now: Instant) {
        let cutoff = now - Duration::from_secs(3600);
        map.retain(|_, record| {
            record.cooldown_until.is_some_and(|c| c > now) || record.last_attempt > cutoff
        });
    }
}

