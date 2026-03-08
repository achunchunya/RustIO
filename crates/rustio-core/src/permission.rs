use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ClusterRead,
    ClusterWrite,
    IamRead,
    IamWrite,
    BucketRead,
    BucketWrite,
    SecurityRead,
    SecurityWrite,
    AuditRead,
    JobsRead,
    JobsWrite,
    ReplicationRead,
    ReplicationWrite,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClusterRead => "cluster:read",
            Self::ClusterWrite => "cluster:write",
            Self::IamRead => "iam:read",
            Self::IamWrite => "iam:write",
            Self::BucketRead => "bucket:read",
            Self::BucketWrite => "bucket:write",
            Self::SecurityRead => "security:read",
            Self::SecurityWrite => "security:write",
            Self::AuditRead => "audit:read",
            Self::JobsRead => "jobs:read",
            Self::JobsWrite => "jobs:write",
            Self::ReplicationRead => "replication:read",
            Self::ReplicationWrite => "replication:write",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "cluster:read" => Some(Self::ClusterRead),
            "cluster:write" => Some(Self::ClusterWrite),
            "iam:read" => Some(Self::IamRead),
            "iam:write" => Some(Self::IamWrite),
            "bucket:read" => Some(Self::BucketRead),
            "bucket:write" => Some(Self::BucketWrite),
            "security:read" => Some(Self::SecurityRead),
            "security:write" => Some(Self::SecurityWrite),
            "audit:read" => Some(Self::AuditRead),
            "jobs:read" => Some(Self::JobsRead),
            "jobs:write" => Some(Self::JobsWrite),
            "replication:read" => Some(Self::ReplicationRead),
            "replication:write" => Some(Self::ReplicationWrite),
            _ => None,
        }
    }
}

pub fn permissions_for_role(role: &str) -> Vec<Permission> {
    match role {
        "admin" => vec![
            Permission::ClusterRead,
            Permission::ClusterWrite,
            Permission::IamRead,
            Permission::IamWrite,
            Permission::BucketRead,
            Permission::BucketWrite,
            Permission::SecurityRead,
            Permission::SecurityWrite,
            Permission::AuditRead,
            Permission::JobsRead,
            Permission::JobsWrite,
            Permission::ReplicationRead,
            Permission::ReplicationWrite,
        ],
        "operator" => vec![
            Permission::ClusterRead,
            Permission::ClusterWrite,
            Permission::BucketRead,
            Permission::BucketWrite,
            Permission::SecurityRead,
            Permission::JobsRead,
            Permission::JobsWrite,
            Permission::ReplicationRead,
            Permission::ReplicationWrite,
            Permission::AuditRead,
        ],
        "auditor" => vec![
            Permission::ClusterRead,
            Permission::IamRead,
            Permission::BucketRead,
            Permission::SecurityRead,
            Permission::AuditRead,
            Permission::JobsRead,
            Permission::ReplicationRead,
        ],
        _ => vec![],
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClaims {
    pub sub: String,
    pub role: String,
    pub permissions: Vec<String>,
    #[serde(default)]
    pub session_id: String,
    #[serde(default = "default_auth_token_use")]
    pub token_use: String,
    pub iat: i64,
    pub exp: i64,
}

fn default_auth_token_use() -> String {
    "access".to_string()
}

impl AuthClaims {
    pub fn issued_at(&self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(self.iat, 0)
    }

    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(self.exp, 0)
    }

    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.iter().any(|p| p == permission.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}
