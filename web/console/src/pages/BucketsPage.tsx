import { useEffect, useMemo, useState } from 'react';
import { toBilingualNotice, toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { bucketService } from '../api/services';
import type {
  BucketAclConfig,
  BucketCorsRule,
  BucketEncryptionConfig,
  BucketLegalHoldConfig,
  BucketLifecycleRule,
  BucketNotificationRule,
  BucketObjectLockConfig,
  BucketPublicAccessBlockConfig,
  BucketRetentionConfig,
  BucketSpec,
  BucketTag
} from '../types';

type BucketsPageProps = {
  client: ApiClient;
};

type GovernanceDraft = {
  versioning: boolean;
  object_lock: boolean;
  ilm_policy: string;
  replication_policy: string;
};

type CorsRuleDraft = {
  id: string;
  allowed_origins: string;
  allowed_methods: string;
  allowed_headers: string;
  expose_headers: string;
  max_age_seconds: string;
};

type TagDraft = {
  key: string;
  value: string;
};

type EncryptionDraft = {
  enabled: boolean;
  algorithm: string;
  kms_key_id: string;
};

type LifecycleRuleDraft = {
  id: string;
  prefix: string;
  status: string;
  expiration_days: string;
  noncurrent_expiration_days: string;
};

function defaultObjectLockConfig(enabled: boolean): BucketObjectLockConfig {
  return {
    enabled,
    mode: 'GOVERNANCE',
    default_retention_days: 30
  };
}

function defaultRetentionConfig(): BucketRetentionConfig {
  return {
    enabled: false,
    mode: 'GOVERNANCE',
    duration_days: 30
  };
}

function defaultLegalHoldConfig(): BucketLegalHoldConfig {
  return { enabled: false };
}

function defaultAclConfig(): BucketAclConfig {
  return { acl: 'private' };
}

function defaultPublicAccessBlockConfig(): BucketPublicAccessBlockConfig {
  return {
    block_public_acls: false,
    ignore_public_acls: false,
    block_public_policy: false,
    restrict_public_buckets: false
  };
}

function defaultNotificationRule(): BucketNotificationRule {
  return {
    id: '',
    event: 's3:ObjectCreated:*',
    target: 'arn:rustio:sqs::primary',
    prefix: '',
    suffix: '',
    enabled: true
  };
}

function normalizeRule(rule: BucketNotificationRule): BucketNotificationRule {
  return {
    id: rule.id.trim(),
    event: rule.event.trim(),
    target: rule.target.trim(),
    prefix: rule.prefix?.trim() || undefined,
    suffix: rule.suffix?.trim() || undefined,
    enabled: rule.enabled
  };
}

function defaultCorsRuleDraft(): CorsRuleDraft {
  return {
    id: '',
    allowed_origins: '*',
    allowed_methods: 'GET,PUT,POST,DELETE,HEAD',
    allowed_headers: '*',
    expose_headers: '',
    max_age_seconds: ''
  };
}

function toCorsRuleDraft(rule: BucketCorsRule): CorsRuleDraft {
  return {
    id: rule.id,
    allowed_origins: rule.allowed_origins.join(','),
    allowed_methods: rule.allowed_methods.join(','),
    allowed_headers: rule.allowed_headers.join(','),
    expose_headers: rule.expose_headers.join(','),
    max_age_seconds:
      typeof rule.max_age_seconds === 'number' ? String(rule.max_age_seconds) : ''
  };
}

function normalizeCorsRuleDraft(draft: CorsRuleDraft): BucketCorsRule {
  const split = (raw: string) =>
    raw
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0);

  const id = draft.id.trim();
  if (!id) {
    throw new Error('CORS 规则 ID 不能为空');
  }
  const allowed_origins = split(draft.allowed_origins);
  if (allowed_origins.length === 0) {
    throw new Error(`CORS 规则 ${id} 缺少 AllowedOrigin`);
  }
  const allowed_methods = split(draft.allowed_methods).map((item) => item.toUpperCase());
  if (allowed_methods.length === 0) {
    throw new Error(`CORS 规则 ${id} 缺少 AllowedMethod`);
  }

  const maxAgeRaw = draft.max_age_seconds.trim();
  const maxAge = maxAgeRaw ? Number(maxAgeRaw) : undefined;
  if (typeof maxAge === 'number' && (!Number.isFinite(maxAge) || maxAge < 0)) {
    throw new Error(`CORS 规则 ${id} 的 MaxAgeSeconds 必须是大于等于 0 的数字`);
  }

  return {
    id,
    allowed_origins,
    allowed_methods,
    allowed_headers: split(draft.allowed_headers),
    expose_headers: split(draft.expose_headers),
    max_age_seconds: maxAge
  };
}

function defaultTagDraft(): TagDraft {
  return {
    key: '',
    value: ''
  };
}

function normalizeTagDraft(tag: TagDraft): BucketTag {
  const key = tag.key.trim();
  if (!key) {
    throw new Error('标签 Key 不能为空');
  }
  return {
    key,
    value: tag.value.trim()
  };
}

function defaultEncryptionDraft(): EncryptionDraft {
  return {
    enabled: false,
    algorithm: 'AES256',
    kms_key_id: ''
  };
}

function toEncryptionDraft(config: BucketEncryptionConfig): EncryptionDraft {
  return {
    enabled: config.enabled,
    algorithm: config.algorithm || 'AES256',
    kms_key_id: config.kms_key_id ?? ''
  };
}

function normalizeEncryptionDraft(draft: EncryptionDraft): BucketEncryptionConfig {
  return {
    enabled: draft.enabled,
    algorithm: draft.algorithm.trim() || 'AES256',
    kms_key_id: draft.kms_key_id.trim() || undefined
  };
}

function defaultLifecycleRuleDraft(): LifecycleRuleDraft {
  return {
    id: '',
    prefix: '',
    status: 'Enabled',
    expiration_days: '30',
    noncurrent_expiration_days: ''
  };
}

function toLifecycleRuleDraft(rule: BucketLifecycleRule): LifecycleRuleDraft {
  return {
    id: rule.id,
    prefix: rule.prefix ?? '',
    status: rule.status || 'Enabled',
    expiration_days:
      typeof rule.expiration_days === 'number' ? String(rule.expiration_days) : '',
    noncurrent_expiration_days:
      typeof rule.noncurrent_expiration_days === 'number'
        ? String(rule.noncurrent_expiration_days)
        : ''
  };
}

function normalizeLifecycleRuleDraft(draft: LifecycleRuleDraft): BucketLifecycleRule {
  const id = draft.id.trim();
  if (!id) {
    throw new Error('生命周期规则 ID 不能为空');
  }
  const status = draft.status.trim();
  if (status !== 'Enabled' && status !== 'Disabled') {
    throw new Error(`生命周期规则 ${id} 的状态必须是 Enabled 或 Disabled`);
  }

  const toPositiveInt = (raw: string, label: string) => {
    const value = raw.trim();
    if (!value) return undefined;
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed <= 0) {
      throw new Error(`生命周期规则 ${id} 的 ${label} 必须为正整数`);
    }
    return parsed;
  };

  const expirationDays = toPositiveInt(draft.expiration_days, 'Expiration Days');
  const noncurrentDays = toPositiveInt(
    draft.noncurrent_expiration_days,
    'Noncurrent Expiration Days'
  );
  if (typeof expirationDays === 'undefined' && typeof noncurrentDays === 'undefined') {
    throw new Error(`生命周期规则 ${id} 至少需要一个过期条件`);
  }

  return {
    id,
    prefix: draft.prefix.trim() || undefined,
    status,
    expiration_days: expirationDays,
    noncurrent_expiration_days: noncurrentDays
  };
}

export function BucketsPage({ client }: BucketsPageProps) {
  const [buckets, setBuckets] = useState<BucketSpec[]>([]);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [creating, setCreating] = useState(false);
  const [savingKey, setSavingKey] = useState('');
  const [drafts, setDrafts] = useState<Record<string, GovernanceDraft>>({});
  const [objectLockDrafts, setObjectLockDrafts] = useState<Record<string, BucketObjectLockConfig>>({});
  const [retentionDrafts, setRetentionDrafts] = useState<Record<string, BucketRetentionConfig>>({});
  const [legalHoldDrafts, setLegalHoldDrafts] = useState<Record<string, BucketLegalHoldConfig>>({});
  const [aclDrafts, setAclDrafts] = useState<Record<string, BucketAclConfig>>({});
  const [publicAccessBlockDrafts, setPublicAccessBlockDrafts] = useState<
    Record<string, BucketPublicAccessBlockConfig>
  >({});
  const [notificationDrafts, setNotificationDrafts] = useState<Record<string, BucketNotificationRule[]>>({});
  const [newRuleDrafts, setNewRuleDrafts] = useState<Record<string, BucketNotificationRule>>({});
  const [lifecycleDrafts, setLifecycleDrafts] = useState<Record<string, LifecycleRuleDraft[]>>({});
  const [newLifecycleRuleDrafts, setNewLifecycleRuleDrafts] = useState<
    Record<string, LifecycleRuleDraft>
  >({});
  const [policyDrafts, setPolicyDrafts] = useState<Record<string, string>>({});
  const [corsDrafts, setCorsDrafts] = useState<Record<string, CorsRuleDraft[]>>({});
  const [newCorsRuleDrafts, setNewCorsRuleDrafts] = useState<Record<string, CorsRuleDraft>>({});
  const [tagDrafts, setTagDrafts] = useState<Record<string, TagDraft[]>>({});
  const [newTagDrafts, setNewTagDrafts] = useState<Record<string, TagDraft>>({});
  const [encryptionDrafts, setEncryptionDrafts] = useState<Record<string, EncryptionDraft>>({});
  const [newBucket, setNewBucket] = useState({
    name: '',
    tenant_id: 'default',
    versioning: true,
    object_lock: false,
    ilm_policy: '',
    replication_policy: ''
  });

  async function reload() {
    const rows = await bucketService.buckets(client);
    setBuckets(rows);

    const nextGovernance: Record<string, GovernanceDraft> = {};
    for (const bucket of rows) {
      nextGovernance[bucket.name] = {
        versioning: bucket.versioning,
        object_lock: bucket.object_lock,
        ilm_policy: bucket.ilm_policy ?? '',
        replication_policy: bucket.replication_policy ?? ''
      };
    }
    setDrafts(nextGovernance);

    const advancedEntries = await Promise.all(
      rows.map(async (bucket) => {
        const [
          objectLock,
          retention,
          legalHold,
          acl,
          publicAccessBlock,
          notifications,
          lifecycle,
          policy,
          corsRules,
          tags,
          encryption
        ] = await Promise.all([
          bucketService.objectLock(client, bucket.name).catch(() => defaultObjectLockConfig(bucket.object_lock)),
          bucketService.retention(client, bucket.name).catch(() => defaultRetentionConfig()),
          bucketService.legalHold(client, bucket.name).catch(() => defaultLegalHoldConfig()),
          bucketService.acl(client, bucket.name).catch(() => defaultAclConfig()),
          bucketService
            .publicAccessBlock(client, bucket.name)
            .catch(() => defaultPublicAccessBlockConfig()),
          bucketService.notifications(client, bucket.name).catch(() => [] as BucketNotificationRule[]),
          bucketService.lifecycle(client, bucket.name).catch(() => [] as BucketLifecycleRule[]),
          bucketService.policy(client, bucket.name).catch(() => null as Record<string, unknown> | null),
          bucketService.cors(client, bucket.name).catch(() => [] as BucketCorsRule[]),
          bucketService.tags(client, bucket.name).catch(() => [] as BucketTag[]),
          bucketService.encryption(client, bucket.name).catch(() => null as BucketEncryptionConfig | null)
        ]);

        return {
          name: bucket.name,
          objectLock,
          retention,
          legalHold,
          acl,
          publicAccessBlock,
          notifications: notifications.map((rule) => ({
            ...rule,
            prefix: rule.prefix ?? '',
            suffix: rule.suffix ?? ''
          })),
          lifecycleRules: lifecycle.map(toLifecycleRuleDraft),
          policyText: policy ? JSON.stringify(policy, null, 2) : '',
          corsRules: corsRules.map(toCorsRuleDraft),
          tags: tags.map((tag) => ({ key: tag.key, value: tag.value })),
          encryption: encryption ? toEncryptionDraft(encryption) : defaultEncryptionDraft()
        };
      })
    );

    setObjectLockDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.objectLock]))
    );
    setRetentionDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.retention]))
    );
    setLegalHoldDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.legalHold]))
    );
    setAclDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.acl]))
    );
    setPublicAccessBlockDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.publicAccessBlock]))
    );
    setNotificationDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.notifications]))
    );
    setLifecycleDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.lifecycleRules]))
    );
    setPolicyDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.policyText]))
    );
    setCorsDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.corsRules]))
    );
    setTagDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.tags]))
    );
    setEncryptionDrafts(
      Object.fromEntries(advancedEntries.map((entry) => [entry.name, entry.encryption]))
    );
    setNewRuleDrafts(
      Object.fromEntries(rows.map((bucket) => [bucket.name, defaultNotificationRule()]))
    );
    setNewLifecycleRuleDrafts(
      Object.fromEntries(rows.map((bucket) => [bucket.name, defaultLifecycleRuleDraft()]))
    );
    setNewCorsRuleDrafts(
      Object.fromEntries(rows.map((bucket) => [bucket.name, defaultCorsRuleDraft()]))
    );
    setNewTagDrafts(
      Object.fromEntries(rows.map((bucket) => [bucket.name, defaultTagDraft()]))
    );
  }

  useEffect(() => {
    reload().catch((requestError) => {
      setError(requestError instanceof Error ? requestError.message : '加载桶列表失败');
    });
  }, [client]);

  const sortedBuckets = useMemo(
    () => [...buckets].sort((left, right) => left.name.localeCompare(right.name)),
    [buckets]
  );

  return (
    <section className="space-y-4">
      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h1 className="font-heading text-2xl text-white">桶治理</h1>
        <p className="mt-1 text-sm text-slate-300">
          版本控制、对象锁、保留策略、法律保留、Policy/CORS/Tagging/SSE 与事件通知全可视化操作。
        </p>
        {error ? <p className="mt-3 text-sm text-rose-400">{toBilingualPrompt(error)}</p> : null}
        {message ? <p className="mt-3 text-sm text-signal-500">{toBilingualNotice(message)}</p> : null}

        <form
          className="mt-4 grid gap-3 rounded-xl border border-white/10 bg-black/10 p-4 md:grid-cols-2"
          onSubmit={async (event) => {
            event.preventDefault();
            setCreating(true);
            setError('');
            setMessage('');
            try {
              await bucketService.createBucket(client, {
                name: newBucket.name,
                tenant_id: newBucket.tenant_id,
                versioning: newBucket.versioning,
                object_lock: newBucket.object_lock,
                ilm_policy: newBucket.ilm_policy || undefined,
                replication_policy: newBucket.replication_policy || undefined
              });
              setMessage(`桶 ${newBucket.name} 创建成功`);
              setNewBucket({
                name: '',
                tenant_id: 'default',
                versioning: true,
                object_lock: false,
                ilm_policy: '',
                replication_policy: ''
              });
              await reload();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '创建桶失败');
            } finally {
              setCreating(false);
            }
          }}
        >
          <label className="text-sm text-slate-300">
            桶名称
            <input
              required
              value={newBucket.name}
              onChange={(event) => setNewBucket((current) => ({ ...current, name: event.target.value }))}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
            />
          </label>
          <label className="text-sm text-slate-300">
            租户
            <input
              required
              value={newBucket.tenant_id}
              onChange={(event) => setNewBucket((current) => ({ ...current, tenant_id: event.target.value }))}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
            />
          </label>
          <label className="text-sm text-slate-300">
            ILM 策略
            <input
              value={newBucket.ilm_policy}
              onChange={(event) => setNewBucket((current) => ({ ...current, ilm_policy: event.target.value }))}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
              placeholder="可选"
            />
          </label>
          <label className="text-sm text-slate-300">
            复制策略
            <input
              value={newBucket.replication_policy}
              onChange={(event) =>
                setNewBucket((current) => ({ ...current, replication_policy: event.target.value }))
              }
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
              placeholder="可选"
            />
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={newBucket.versioning}
              onChange={(event) => setNewBucket((current) => ({ ...current, versioning: event.target.checked }))}
            />
            启用版本控制
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={newBucket.object_lock}
              onChange={(event) => setNewBucket((current) => ({ ...current, object_lock: event.target.checked }))}
            />
            启用对象锁
          </label>
          <div className="md:col-span-2">
            <button
              type="submit"
              disabled={creating}
              className="h-11 rounded-md bg-signal-600 px-4 text-sm font-medium text-white disabled:opacity-60"
            >
              {creating ? '创建中...' : '创建桶'}
            </button>
          </div>
        </form>
      </article>

      <div className="space-y-4">
        {sortedBuckets.map((bucket) => {
          const governanceDraft = drafts[bucket.name] ?? {
            versioning: bucket.versioning,
            object_lock: bucket.object_lock,
            ilm_policy: bucket.ilm_policy ?? '',
            replication_policy: bucket.replication_policy ?? ''
          };
          const objectLock =
            objectLockDrafts[bucket.name] ?? defaultObjectLockConfig(governanceDraft.object_lock);
          const retention = retentionDrafts[bucket.name] ?? defaultRetentionConfig();
          const legalHold = legalHoldDrafts[bucket.name] ?? defaultLegalHoldConfig();
          const acl = aclDrafts[bucket.name] ?? defaultAclConfig();
          const publicAccessBlock =
            publicAccessBlockDrafts[bucket.name] ?? defaultPublicAccessBlockConfig();
          const notificationRules = notificationDrafts[bucket.name] ?? [];
          const newRule = newRuleDrafts[bucket.name] ?? defaultNotificationRule();
          const lifecycleRules = lifecycleDrafts[bucket.name] ?? [];
          const newLifecycleRule =
            newLifecycleRuleDrafts[bucket.name] ?? defaultLifecycleRuleDraft();
          const policyText = policyDrafts[bucket.name] ?? '';
          const corsRules = corsDrafts[bucket.name] ?? [];
          const newCorsRule = newCorsRuleDrafts[bucket.name] ?? defaultCorsRuleDraft();
          const tags = tagDrafts[bucket.name] ?? [];
          const newTag = newTagDrafts[bucket.name] ?? defaultTagDraft();
          const encryption = encryptionDrafts[bucket.name] ?? defaultEncryptionDraft();

          return (
            <article key={bucket.name} className="rounded-xl border border-white/10 bg-ink-800/70 p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-heading text-lg text-white">{bucket.name}</p>
                  <p className="mt-1 text-xs text-slate-400">租户：{bucket.tenant_id}</p>
                </div>
                <button
                  className="h-9 rounded-md border border-rose-500/40 px-3 text-xs text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                  disabled={savingKey === `${bucket.name}:delete`}
                  onClick={async () => {
                    if (!window.confirm(`确认删除桶 ${bucket.name}？仅允许删除空桶。`)) return;
                    setSavingKey(`${bucket.name}:delete`);
                    setError('');
                    setMessage('');
                    try {
                      await bucketService.deleteBucket(client, bucket.name);
                      setMessage(`桶 ${bucket.name} 已删除`);
                      await reload();
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '删除桶失败');
                    } finally {
                      setSavingKey('');
                    }
                  }}
                >
                  {savingKey === `${bucket.name}:delete` ? '删除中...' : '删除桶'}
                </button>
              </div>

              <div className="mt-4 rounded-lg border border-white/10 bg-black/10 p-3">
                <h3 className="text-sm font-medium text-white">生命周期规则（Lifecycle）</h3>
                <p className="mt-1 text-xs text-slate-400">
                  对齐企业级对象存储生命周期治理，支持当前版本和非当前版本过期策略。
                </p>
                <div className="mt-3 space-y-2">
                  {lifecycleRules.length === 0 ? (
                    <p className="text-xs text-slate-500">未配置生命周期规则</p>
                  ) : (
                    lifecycleRules.map((rule, index) => (
                      <div
                        key={`${bucket.name}:lifecycle:${rule.id || index}`}
                        className="grid gap-2 rounded-md border border-white/10 p-2 md:grid-cols-6"
                      >
                        <input
                          value={rule.id}
                          onChange={(event) =>
                            setLifecycleDrafts((current) => ({
                              ...current,
                              [bucket.name]: lifecycleRules.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, id: event.target.value } : item
                              )
                            }))
                          }
                          placeholder="规则 ID"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={rule.prefix}
                          onChange={(event) =>
                            setLifecycleDrafts((current) => ({
                              ...current,
                              [bucket.name]: lifecycleRules.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, prefix: event.target.value } : item
                              )
                            }))
                          }
                          placeholder="Prefix（可选）"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <select
                          value={rule.status}
                          onChange={(event) =>
                            setLifecycleDrafts((current) => ({
                              ...current,
                              [bucket.name]: lifecycleRules.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, status: event.target.value } : item
                              )
                            }))
                          }
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        >
                          <option value="Enabled">Enabled</option>
                          <option value="Disabled">Disabled</option>
                        </select>
                        <input
                          value={rule.expiration_days}
                          onChange={(event) =>
                            setLifecycleDrafts((current) => ({
                              ...current,
                              [bucket.name]: lifecycleRules.map((item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, expiration_days: event.target.value }
                                  : item
                              )
                            }))
                          }
                          placeholder="Expiration Days"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={rule.noncurrent_expiration_days}
                          onChange={(event) =>
                            setLifecycleDrafts((current) => ({
                              ...current,
                              [bucket.name]: lifecycleRules.map((item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, noncurrent_expiration_days: event.target.value }
                                  : item
                              )
                            }))
                          }
                          placeholder="Noncurrent Days"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <div className="flex items-center justify-end">
                          <button
                            className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10"
                            onClick={() =>
                              setLifecycleDrafts((current) => ({
                                ...current,
                                [bucket.name]: lifecycleRules.filter((_, itemIndex) => itemIndex !== index)
                              }))
                            }
                          >
                            删除
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <div className="mt-3 grid gap-2 rounded-md border border-white/10 p-2 md:grid-cols-6">
                  <input
                    value={newLifecycleRule.id}
                    onChange={(event) =>
                      setNewLifecycleRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newLifecycleRule, id: event.target.value }
                      }))
                    }
                    placeholder="规则 ID"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newLifecycleRule.prefix}
                    onChange={(event) =>
                      setNewLifecycleRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newLifecycleRule, prefix: event.target.value }
                      }))
                    }
                    placeholder="Prefix（可选）"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <select
                    value={newLifecycleRule.status}
                    onChange={(event) =>
                      setNewLifecycleRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newLifecycleRule, status: event.target.value }
                      }))
                    }
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  >
                    <option value="Enabled">Enabled</option>
                    <option value="Disabled">Disabled</option>
                  </select>
                  <input
                    value={newLifecycleRule.expiration_days}
                    onChange={(event) =>
                      setNewLifecycleRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newLifecycleRule, expiration_days: event.target.value }
                      }))
                    }
                    placeholder="Expiration Days"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newLifecycleRule.noncurrent_expiration_days}
                    onChange={(event) =>
                      setNewLifecycleRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: {
                          ...newLifecycleRule,
                          noncurrent_expiration_days: event.target.value
                        }
                      }))
                    }
                    placeholder="Noncurrent Days"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <div className="flex items-center justify-end">
                    <button
                      className="rounded-md border border-white/15 px-2 py-1 text-xs text-slate-200 hover:bg-white/5"
                      onClick={() => {
                        try {
                          const normalized = normalizeLifecycleRuleDraft(newLifecycleRule);
                          if (lifecycleRules.some((rule) => rule.id.trim() === normalized.id)) {
                            throw new Error(`生命周期规则 ID ${normalized.id} 已存在`);
                          }
                          setLifecycleDrafts((current) => ({
                            ...current,
                            [bucket.name]: [...lifecycleRules, toLifecycleRuleDraft(normalized)]
                          }));
                          setNewLifecycleRuleDrafts((current) => ({
                            ...current,
                            [bucket.name]: defaultLifecycleRuleDraft()
                          }));
                          setError('');
                        } catch (requestError) {
                          setError(
                            requestError instanceof Error ? requestError.message : '新增生命周期规则失败'
                          );
                        }
                      }}
                    >
                      新增规则
                    </button>
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                    disabled={savingKey === `${bucket.name}:lifecycle`}
                    onClick={async () => {
                      setSavingKey(`${bucket.name}:lifecycle`);
                      setError('');
                      setMessage('');
                      try {
                        const payload = lifecycleRules.map(normalizeLifecycleRuleDraft);
                        const ids = new Set(payload.map((rule) => rule.id));
                        if (ids.size !== payload.length) {
                          throw new Error('生命周期规则 ID 不能重复');
                        }
                        await bucketService.updateLifecycle(client, bucket.name, payload);
                        setMessage(`桶 ${bucket.name} 的生命周期规则已更新`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '更新生命周期规则失败');
                      } finally {
                        setSavingKey('');
                      }
                    }}
                  >
                    {savingKey === `${bucket.name}:lifecycle` ? '保存中...' : '保存生命周期规则'}
                  </button>
                  <button
                    className="h-10 rounded-md border border-rose-500/40 px-3 text-sm text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                    disabled={savingKey === `${bucket.name}:lifecycle-clear`}
                    onClick={async () => {
                      if (!window.confirm(`确认清除桶 ${bucket.name} 的生命周期配置？`)) return;
                      setSavingKey(`${bucket.name}:lifecycle-clear`);
                      setError('');
                      setMessage('');
                      try {
                        await bucketService.deleteLifecycle(client, bucket.name);
                        setMessage(`桶 ${bucket.name} 的生命周期配置已清除`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '清除生命周期配置失败');
                      } finally {
                        setSavingKey('');
                      }
                    }}
                  >
                    {savingKey === `${bucket.name}:lifecycle-clear` ? '处理中...' : '清除生命周期'}
                  </button>
                </div>
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div className="rounded-lg border border-white/10 bg-black/10 p-3">
                  <h3 className="text-sm font-medium text-white">基础治理</h3>
                  <div className="mt-3 grid gap-2">
                    <label className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={governanceDraft.versioning}
                        onChange={(event) =>
                          setDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...governanceDraft,
                              versioning: event.target.checked
                            }
                          }))
                        }
                      />
                      版本控制
                    </label>
                    <label className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={governanceDraft.object_lock}
                        onChange={(event) =>
                          setDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...governanceDraft,
                              object_lock: event.target.checked
                            }
                          }))
                        }
                      />
                      对象锁
                    </label>
                    <label className="text-xs text-slate-400">
                      ILM 策略
                      <input
                        value={governanceDraft.ilm_policy}
                        onChange={(event) =>
                          setDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...governanceDraft,
                              ilm_policy: event.target.value
                            }
                          }))
                        }
                        className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                      />
                    </label>
                    <label className="text-xs text-slate-400">
                      复制策略
                      <input
                        value={governanceDraft.replication_policy}
                        onChange={(event) =>
                          setDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...governanceDraft,
                              replication_policy: event.target.value
                            }
                          }))
                        }
                        className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                      />
                    </label>
                    <button
                      className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                      disabled={savingKey === `${bucket.name}:governance`}
                      onClick={async () => {
                        setSavingKey(`${bucket.name}:governance`);
                        setError('');
                        setMessage('');
                        try {
                          await bucketService.updateGovernance(client, bucket.name, {
                            versioning: governanceDraft.versioning,
                            object_lock: governanceDraft.object_lock,
                            ilm_policy: governanceDraft.ilm_policy || undefined,
                            replication_policy: governanceDraft.replication_policy || undefined
                          });
                          setMessage(`桶 ${bucket.name} 基础治理已更新`);
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '更新基础治理失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      {savingKey === `${bucket.name}:governance` ? '保存中...' : '保存基础治理'}
                    </button>
                  </div>
                </div>

                <div className="rounded-lg border border-white/10 bg-black/10 p-3">
                  <h3 className="text-sm font-medium text-white">对象锁默认保留</h3>
                  <div className="mt-3 grid gap-2">
                    <label className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={objectLock.enabled}
                        onChange={(event) =>
                          setObjectLockDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...objectLock,
                              enabled: event.target.checked
                            }
                          }))
                        }
                      />
                      启用 Object Lock 默认规则
                    </label>
                    <label className="text-xs text-slate-400">
                      模式
                      <select
                        value={objectLock.mode}
                        onChange={(event) =>
                          setObjectLockDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...objectLock,
                              mode: event.target.value
                            }
                          }))
                        }
                        className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                      >
                        <option value="GOVERNANCE">GOVERNANCE</option>
                        <option value="COMPLIANCE">COMPLIANCE</option>
                      </select>
                    </label>
                    <label className="text-xs text-slate-400">
                      默认保留天数
                      <input
                        type="number"
                        min={1}
                        value={objectLock.default_retention_days}
                        onChange={(event) =>
                          setObjectLockDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...objectLock,
                              default_retention_days: Number(event.target.value)
                            }
                          }))
                        }
                        className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                      />
                    </label>
                    <button
                      className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                      disabled={savingKey === `${bucket.name}:object-lock`}
                      onClick={async () => {
                        setSavingKey(`${bucket.name}:object-lock`);
                        setError('');
                        setMessage('');
                        try {
                          await bucketService.updateObjectLock(client, bucket.name, objectLock);
                          setMessage(`桶 ${bucket.name} 的 Object Lock 配置已更新`);
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '更新 Object Lock 失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      {savingKey === `${bucket.name}:object-lock` ? '保存中...' : '保存 Object Lock'}
                    </button>
                  </div>
                </div>

                <div className="rounded-lg border border-white/10 bg-black/10 p-3">
                  <h3 className="text-sm font-medium text-white">默认保留策略</h3>
                  <div className="mt-3 grid gap-2">
                    <label className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={retention.enabled}
                        onChange={(event) =>
                          setRetentionDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...retention,
                              enabled: event.target.checked
                            }
                          }))
                        }
                      />
                      启用默认保留
                    </label>
                    <label className="text-xs text-slate-400">
                      模式
                      <select
                        value={retention.mode}
                        onChange={(event) =>
                          setRetentionDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...retention,
                              mode: event.target.value
                            }
                          }))
                        }
                        className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                      >
                        <option value="GOVERNANCE">GOVERNANCE</option>
                        <option value="COMPLIANCE">COMPLIANCE</option>
                      </select>
                    </label>
                    <label className="text-xs text-slate-400">
                      保留天数
                      <input
                        type="number"
                        min={1}
                        value={retention.duration_days}
                        onChange={(event) =>
                          setRetentionDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...retention,
                              duration_days: Number(event.target.value)
                            }
                          }))
                        }
                        className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                      />
                    </label>
                    <button
                      className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                      disabled={savingKey === `${bucket.name}:retention`}
                      onClick={async () => {
                        setSavingKey(`${bucket.name}:retention`);
                        setError('');
                        setMessage('');
                        try {
                          await bucketService.updateRetention(client, bucket.name, retention);
                          setMessage(`桶 ${bucket.name} 的默认保留策略已更新`);
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '更新默认保留失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      {savingKey === `${bucket.name}:retention` ? '保存中...' : '保存默认保留'}
                    </button>
                  </div>
                </div>

                <div className="rounded-lg border border-white/10 bg-black/10 p-3">
                  <h3 className="text-sm font-medium text-white">法律保留</h3>
                  <div className="mt-3 grid gap-2">
                    <label className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={legalHold.enabled}
                        onChange={(event) =>
                          setLegalHoldDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              enabled: event.target.checked
                            }
                          }))
                        }
                      />
                      启用法律保留
                    </label>
                    <button
                      className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                      disabled={savingKey === `${bucket.name}:legal-hold`}
                      onClick={async () => {
                        setSavingKey(`${bucket.name}:legal-hold`);
                        setError('');
                        setMessage('');
                        try {
                          await bucketService.updateLegalHold(client, bucket.name, legalHold);
                          setMessage(`桶 ${bucket.name} 的法律保留已更新`);
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '更新法律保留失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      {savingKey === `${bucket.name}:legal-hold` ? '保存中...' : '保存法律保留'}
                    </button>
                  </div>
                </div>

                <div className="rounded-lg border border-white/10 bg-black/10 p-3">
                  <h3 className="text-sm font-medium text-white">访问控制（ACL / Public Access）</h3>
                  <div className="mt-3 grid gap-2">
                    <label className="text-xs text-slate-400">
                      桶 ACL
                      <select
                        value={acl.acl}
                        onChange={(event) =>
                          setAclDrafts((current) => ({
                            ...current,
                            [bucket.name]: { acl: event.target.value }
                          }))
                        }
                        className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                      >
                        <option value="private">private</option>
                        <option value="public-read">public-read</option>
                        <option value="public-read-write">public-read-write</option>
                        <option value="authenticated-read">authenticated-read</option>
                      </select>
                    </label>
                    <button
                      className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                      disabled={savingKey === `${bucket.name}:acl`}
                      onClick={async () => {
                        setSavingKey(`${bucket.name}:acl`);
                        setError('');
                        setMessage('');
                        try {
                          await bucketService.updateAcl(client, bucket.name, acl);
                          setMessage(`桶 ${bucket.name} ACL 已更新`);
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '更新桶 ACL 失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      {savingKey === `${bucket.name}:acl` ? '保存中...' : '保存 ACL'}
                    </button>

                    <label className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={publicAccessBlock.block_public_acls}
                        onChange={(event) =>
                          setPublicAccessBlockDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...publicAccessBlock,
                              block_public_acls: event.target.checked
                            }
                          }))
                        }
                      />
                      Block Public ACLs
                    </label>
                    <label className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={publicAccessBlock.ignore_public_acls}
                        onChange={(event) =>
                          setPublicAccessBlockDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...publicAccessBlock,
                              ignore_public_acls: event.target.checked
                            }
                          }))
                        }
                      />
                      Ignore Public ACLs
                    </label>
                    <label className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={publicAccessBlock.block_public_policy}
                        onChange={(event) =>
                          setPublicAccessBlockDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...publicAccessBlock,
                              block_public_policy: event.target.checked
                            }
                          }))
                        }
                      />
                      Block Public Policy
                    </label>
                    <label className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={publicAccessBlock.restrict_public_buckets}
                        onChange={(event) =>
                          setPublicAccessBlockDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...publicAccessBlock,
                              restrict_public_buckets: event.target.checked
                            }
                          }))
                        }
                      />
                      Restrict Public Buckets
                    </label>
                    <div className="flex flex-wrap gap-2">
                      <button
                        className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                        disabled={savingKey === `${bucket.name}:pab`}
                        onClick={async () => {
                          setSavingKey(`${bucket.name}:pab`);
                          setError('');
                          setMessage('');
                          try {
                            await bucketService.updatePublicAccessBlock(
                              client,
                              bucket.name,
                              publicAccessBlock
                            );
                            setMessage(`桶 ${bucket.name} Public Access Block 已更新`);
                            await reload();
                          } catch (requestError) {
                            setError(
                              requestError instanceof Error
                                ? requestError.message
                                : '更新 Public Access Block 失败'
                            );
                          } finally {
                            setSavingKey('');
                          }
                        }}
                      >
                        {savingKey === `${bucket.name}:pab` ? '保存中...' : '保存 Public Access'}
                      </button>
                      <button
                        className="h-10 rounded-md border border-rose-500/40 px-3 text-sm text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                        disabled={savingKey === `${bucket.name}:pab-clear`}
                        onClick={async () => {
                          if (!window.confirm(`确认清除桶 ${bucket.name} 的 Public Access Block 配置？`)) {
                            return;
                          }
                          setSavingKey(`${bucket.name}:pab-clear`);
                          setError('');
                          setMessage('');
                          try {
                            await bucketService.deletePublicAccessBlock(client, bucket.name);
                            setMessage(`桶 ${bucket.name} Public Access Block 已清除`);
                            await reload();
                          } catch (requestError) {
                            setError(
                              requestError instanceof Error
                                ? requestError.message
                                : '清除 Public Access Block 失败'
                            );
                          } finally {
                            setSavingKey('');
                          }
                        }}
                      >
                        {savingKey === `${bucket.name}:pab-clear` ? '处理中...' : '清除 Public Access'}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div className="rounded-lg border border-white/10 bg-black/10 p-3">
                  <h3 className="text-sm font-medium text-white">Bucket Policy</h3>
                  <p className="mt-1 text-xs text-slate-400">
                    使用 JSON 直接编辑策略文档，留空并保存可清除策略。
                  </p>
                  <textarea
                    value={policyText}
                    onChange={(event) =>
                      setPolicyDrafts((current) => ({
                        ...current,
                        [bucket.name]: event.target.value
                      }))
                    }
                    className="mt-3 h-56 w-full rounded-md border border-white/15 bg-ink-900 px-3 py-2 text-xs text-slate-100"
                    placeholder='{"Version":"2012-10-17","Statement":[...]}'
                  />
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button
                      className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                      disabled={savingKey === `${bucket.name}:policy`}
                      onClick={async () => {
                        setSavingKey(`${bucket.name}:policy`);
                        setError('');
                        setMessage('');
                        try {
                          const raw = policyText.trim();
                          if (!raw) {
                            await bucketService.deletePolicy(client, bucket.name);
                            setMessage(`桶 ${bucket.name} 的策略已清除`);
                          } else {
                            const parsed = JSON.parse(raw) as Record<string, unknown>;
                            await bucketService.updatePolicy(client, bucket.name, parsed);
                            setMessage(`桶 ${bucket.name} 的策略已更新`);
                          }
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '更新策略失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      {savingKey === `${bucket.name}:policy` ? '保存中...' : '保存策略'}
                    </button>
                    <button
                      className="h-10 rounded-md border border-rose-500/40 px-3 text-sm text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                      disabled={savingKey === `${bucket.name}:policy-clear`}
                      onClick={async () => {
                        if (!window.confirm(`确认清除桶 ${bucket.name} 的策略配置？`)) return;
                        setSavingKey(`${bucket.name}:policy-clear`);
                        setError('');
                        setMessage('');
                        try {
                          await bucketService.deletePolicy(client, bucket.name);
                          setMessage(`桶 ${bucket.name} 的策略已清除`);
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '清除策略失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      {savingKey === `${bucket.name}:policy-clear` ? '处理中...' : '清除策略'}
                    </button>
                  </div>
                </div>

                <div className="rounded-lg border border-white/10 bg-black/10 p-3">
                  <h3 className="text-sm font-medium text-white">默认加密（SSE）</h3>
                  <div className="mt-3 grid gap-2">
                    <label className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={encryption.enabled}
                        onChange={(event) =>
                          setEncryptionDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...encryption,
                              enabled: event.target.checked
                            }
                          }))
                        }
                      />
                      启用桶默认加密
                    </label>
                    <label className="text-xs text-slate-400">
                      算法
                      <select
                        value={encryption.algorithm}
                        onChange={(event) =>
                          setEncryptionDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...encryption,
                              algorithm: event.target.value
                            }
                          }))
                        }
                        className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                      >
                        <option value="AES256">AES256</option>
                        <option value="aws:kms">aws:kms</option>
                      </select>
                    </label>
                    <label className="text-xs text-slate-400">
                      KMS Key ID（可选）
                      <input
                        value={encryption.kms_key_id}
                        onChange={(event) =>
                          setEncryptionDrafts((current) => ({
                            ...current,
                            [bucket.name]: {
                              ...encryption,
                              kms_key_id: event.target.value
                            }
                          }))
                        }
                        placeholder="alias/rustio-default"
                        className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                      />
                    </label>
                    <div className="flex flex-wrap gap-2">
                      <button
                        className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                        disabled={savingKey === `${bucket.name}:encryption`}
                        onClick={async () => {
                          setSavingKey(`${bucket.name}:encryption`);
                          setError('');
                          setMessage('');
                          try {
                            if (!encryption.enabled) {
                              await bucketService.deleteEncryption(client, bucket.name);
                              setMessage(`桶 ${bucket.name} 的默认加密已关闭`);
                            } else {
                              const payload = normalizeEncryptionDraft(encryption);
                              await bucketService.updateEncryption(client, bucket.name, payload);
                              setMessage(`桶 ${bucket.name} 的默认加密已更新`);
                            }
                            await reload();
                          } catch (requestError) {
                            setError(requestError instanceof Error ? requestError.message : '更新默认加密失败');
                          } finally {
                            setSavingKey('');
                          }
                        }}
                      >
                        {savingKey === `${bucket.name}:encryption` ? '保存中...' : '保存加密配置'}
                      </button>
                      <button
                        className="h-10 rounded-md border border-rose-500/40 px-3 text-sm text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                        disabled={savingKey === `${bucket.name}:encryption-clear`}
                        onClick={async () => {
                          if (!window.confirm(`确认删除桶 ${bucket.name} 的默认加密配置？`)) return;
                          setSavingKey(`${bucket.name}:encryption-clear`);
                          setError('');
                          setMessage('');
                          try {
                            await bucketService.deleteEncryption(client, bucket.name);
                            setMessage(`桶 ${bucket.name} 的默认加密已清除`);
                            await reload();
                          } catch (requestError) {
                            setError(requestError instanceof Error ? requestError.message : '清除默认加密失败');
                          } finally {
                            setSavingKey('');
                          }
                        }}
                      >
                        {savingKey === `${bucket.name}:encryption-clear` ? '处理中...' : '清除加密配置'}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-4 rounded-lg border border-white/10 bg-black/10 p-3">
                <h3 className="text-sm font-medium text-white">CORS 规则</h3>
                <div className="mt-3 space-y-2">
                  {corsRules.length === 0 ? (
                    <p className="text-xs text-slate-500">未配置 CORS 规则</p>
                  ) : (
                    corsRules.map((rule, index) => (
                      <div
                        key={`${bucket.name}:cors:${rule.id || index}`}
                        className="grid gap-2 rounded-md border border-white/10 p-2 md:grid-cols-6"
                      >
                        <input
                          value={rule.id}
                          onChange={(event) =>
                            setCorsDrafts((current) => ({
                              ...current,
                              [bucket.name]: corsRules.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, id: event.target.value } : item
                              )
                            }))
                          }
                          placeholder="规则 ID"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={rule.allowed_origins}
                          onChange={(event) =>
                            setCorsDrafts((current) => ({
                              ...current,
                              [bucket.name]: corsRules.map((item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, allowed_origins: event.target.value }
                                  : item
                              )
                            }))
                          }
                          placeholder="AllowedOrigin（逗号分隔）"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={rule.allowed_methods}
                          onChange={(event) =>
                            setCorsDrafts((current) => ({
                              ...current,
                              [bucket.name]: corsRules.map((item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, allowed_methods: event.target.value }
                                  : item
                              )
                            }))
                          }
                          placeholder="AllowedMethod（逗号分隔）"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={rule.allowed_headers}
                          onChange={(event) =>
                            setCorsDrafts((current) => ({
                              ...current,
                              [bucket.name]: corsRules.map((item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, allowed_headers: event.target.value }
                                  : item
                              )
                            }))
                          }
                          placeholder="AllowedHeader"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={rule.expose_headers}
                          onChange={(event) =>
                            setCorsDrafts((current) => ({
                              ...current,
                              [bucket.name]: corsRules.map((item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, expose_headers: event.target.value }
                                  : item
                              )
                            }))
                          }
                          placeholder="ExposeHeader"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <div className="flex items-center justify-between gap-2">
                          <input
                            value={rule.max_age_seconds}
                            onChange={(event) =>
                              setCorsDrafts((current) => ({
                                ...current,
                                [bucket.name]: corsRules.map((item, itemIndex) =>
                                  itemIndex === index
                                    ? { ...item, max_age_seconds: event.target.value }
                                    : item
                                )
                              }))
                            }
                            placeholder="MaxAgeSeconds"
                            className="h-9 w-full rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                          />
                          <button
                            className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10"
                            onClick={() =>
                              setCorsDrafts((current) => ({
                                ...current,
                                [bucket.name]: corsRules.filter((_, itemIndex) => itemIndex !== index)
                              }))
                            }
                          >
                            删除
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <div className="mt-3 grid gap-2 rounded-md border border-white/10 p-2 md:grid-cols-6">
                  <input
                    value={newCorsRule.id}
                    onChange={(event) =>
                      setNewCorsRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newCorsRule, id: event.target.value }
                      }))
                    }
                    placeholder="规则 ID"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newCorsRule.allowed_origins}
                    onChange={(event) =>
                      setNewCorsRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newCorsRule, allowed_origins: event.target.value }
                      }))
                    }
                    placeholder="AllowedOrigin"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newCorsRule.allowed_methods}
                    onChange={(event) =>
                      setNewCorsRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newCorsRule, allowed_methods: event.target.value }
                      }))
                    }
                    placeholder="AllowedMethod"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newCorsRule.allowed_headers}
                    onChange={(event) =>
                      setNewCorsRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newCorsRule, allowed_headers: event.target.value }
                      }))
                    }
                    placeholder="AllowedHeader"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newCorsRule.expose_headers}
                    onChange={(event) =>
                      setNewCorsRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newCorsRule, expose_headers: event.target.value }
                      }))
                    }
                    placeholder="ExposeHeader"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <div className="flex items-center gap-2">
                    <input
                      value={newCorsRule.max_age_seconds}
                      onChange={(event) =>
                        setNewCorsRuleDrafts((current) => ({
                          ...current,
                          [bucket.name]: { ...newCorsRule, max_age_seconds: event.target.value }
                        }))
                      }
                      placeholder="MaxAgeSeconds"
                      className="h-9 w-full rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                    />
                    <button
                      className="rounded-md border border-white/15 px-2 py-1 text-xs text-slate-200 hover:bg-white/5"
                      onClick={() => {
                        try {
                          const normalized = normalizeCorsRuleDraft(newCorsRule);
                          if (corsRules.some((rule) => rule.id.trim() === normalized.id)) {
                            throw new Error(`CORS 规则 ID ${normalized.id} 已存在`);
                          }
                          setCorsDrafts((current) => ({
                            ...current,
                            [bucket.name]: [...corsRules, toCorsRuleDraft(normalized)]
                          }));
                          setNewCorsRuleDrafts((current) => ({
                            ...current,
                            [bucket.name]: defaultCorsRuleDraft()
                          }));
                          setError('');
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '新增 CORS 规则失败');
                        }
                      }}
                    >
                      新增
                    </button>
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                    disabled={savingKey === `${bucket.name}:cors`}
                    onClick={async () => {
                      setSavingKey(`${bucket.name}:cors`);
                      setError('');
                      setMessage('');
                      try {
                        const payload = corsRules.map(normalizeCorsRuleDraft);
                        await bucketService.updateCors(client, bucket.name, payload);
                        setMessage(`桶 ${bucket.name} 的 CORS 规则已更新`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '更新 CORS 失败');
                      } finally {
                        setSavingKey('');
                      }
                    }}
                  >
                    {savingKey === `${bucket.name}:cors` ? '保存中...' : '保存 CORS'}
                  </button>
                  <button
                    className="h-10 rounded-md border border-rose-500/40 px-3 text-sm text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                    disabled={savingKey === `${bucket.name}:cors-clear`}
                    onClick={async () => {
                      if (!window.confirm(`确认删除桶 ${bucket.name} 的 CORS 配置？`)) return;
                      setSavingKey(`${bucket.name}:cors-clear`);
                      setError('');
                      setMessage('');
                      try {
                        await bucketService.deleteCors(client, bucket.name);
                        setMessage(`桶 ${bucket.name} 的 CORS 配置已清除`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '清除 CORS 失败');
                      } finally {
                        setSavingKey('');
                      }
                    }}
                  >
                    {savingKey === `${bucket.name}:cors-clear` ? '处理中...' : '清除 CORS'}
                  </button>
                </div>
              </div>

              <div className="mt-4 rounded-lg border border-white/10 bg-black/10 p-3">
                <h3 className="text-sm font-medium text-white">桶标签（Tagging）</h3>
                <div className="mt-3 space-y-2">
                  {tags.length === 0 ? (
                    <p className="text-xs text-slate-500">未配置标签</p>
                  ) : (
                    tags.map((tag, index) => (
                      <div
                        key={`${bucket.name}:tag:${tag.key || index}`}
                        className="grid gap-2 rounded-md border border-white/10 p-2 md:grid-cols-3"
                      >
                        <input
                          value={tag.key}
                          onChange={(event) =>
                            setTagDrafts((current) => ({
                              ...current,
                              [bucket.name]: tags.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, key: event.target.value } : item
                              )
                            }))
                          }
                          placeholder="Key"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={tag.value}
                          onChange={(event) =>
                            setTagDrafts((current) => ({
                              ...current,
                              [bucket.name]: tags.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, value: event.target.value } : item
                              )
                            }))
                          }
                          placeholder="Value"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <div className="flex items-center justify-end">
                          <button
                            className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10"
                            onClick={() =>
                              setTagDrafts((current) => ({
                                ...current,
                                [bucket.name]: tags.filter((_, itemIndex) => itemIndex !== index)
                              }))
                            }
                          >
                            删除
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <div className="mt-3 grid gap-2 rounded-md border border-white/10 p-2 md:grid-cols-3">
                  <input
                    value={newTag.key}
                    onChange={(event) =>
                      setNewTagDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newTag, key: event.target.value }
                      }))
                    }
                    placeholder="Key"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newTag.value}
                    onChange={(event) =>
                      setNewTagDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newTag, value: event.target.value }
                      }))
                    }
                    placeholder="Value"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <div className="flex items-center justify-end">
                    <button
                      className="rounded-md border border-white/15 px-2 py-1 text-xs text-slate-200 hover:bg-white/5"
                      onClick={() => {
                        try {
                          const normalized = normalizeTagDraft(newTag);
                          if (tags.some((item) => item.key.trim() === normalized.key)) {
                            throw new Error(`标签 Key ${normalized.key} 已存在`);
                          }
                          setTagDrafts((current) => ({
                            ...current,
                            [bucket.name]: [...tags, { key: normalized.key, value: normalized.value }]
                          }));
                          setNewTagDrafts((current) => ({
                            ...current,
                            [bucket.name]: defaultTagDraft()
                          }));
                          setError('');
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '新增标签失败');
                        }
                      }}
                    >
                      新增标签
                    </button>
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                    disabled={savingKey === `${bucket.name}:tags`}
                    onClick={async () => {
                      setSavingKey(`${bucket.name}:tags`);
                      setError('');
                      setMessage('');
                      try {
                        const payload = tags.map(normalizeTagDraft);
                        await bucketService.updateTags(client, bucket.name, payload);
                        setMessage(`桶 ${bucket.name} 的标签已更新`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '更新标签失败');
                      } finally {
                        setSavingKey('');
                      }
                    }}
                  >
                    {savingKey === `${bucket.name}:tags` ? '保存中...' : '保存标签'}
                  </button>
                  <button
                    className="h-10 rounded-md border border-rose-500/40 px-3 text-sm text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                    disabled={savingKey === `${bucket.name}:tags-clear`}
                    onClick={async () => {
                      if (!window.confirm(`确认删除桶 ${bucket.name} 的所有标签？`)) return;
                      setSavingKey(`${bucket.name}:tags-clear`);
                      setError('');
                      setMessage('');
                      try {
                        await bucketService.deleteTags(client, bucket.name);
                        setMessage(`桶 ${bucket.name} 的标签已清除`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '清除标签失败');
                      } finally {
                        setSavingKey('');
                      }
                    }}
                  >
                    {savingKey === `${bucket.name}:tags-clear` ? '处理中...' : '清除标签'}
                  </button>
                </div>
              </div>

              <div className="mt-4 rounded-lg border border-white/10 bg-black/10 p-3">
                <h3 className="text-sm font-medium text-white">事件通知规则</h3>
                <div className="mt-3 space-y-2">
                  {notificationRules.length === 0 ? (
                    <p className="text-xs text-slate-500">暂无通知规则</p>
                  ) : (
                    notificationRules.map((rule, index) => (
                      <div key={`${bucket.name}:${rule.id || index}`} className="grid gap-2 rounded-md border border-white/10 p-2 md:grid-cols-6">
                        <input
                          value={rule.id}
                          onChange={(event) =>
                            setNotificationDrafts((current) => ({
                              ...current,
                              [bucket.name]: notificationRules.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, id: event.target.value } : item
                              )
                            }))
                          }
                          placeholder="规则 ID"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={rule.event}
                          onChange={(event) =>
                            setNotificationDrafts((current) => ({
                              ...current,
                              [bucket.name]: notificationRules.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, event: event.target.value } : item
                              )
                            }))
                          }
                          placeholder="事件"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={rule.target}
                          onChange={(event) =>
                            setNotificationDrafts((current) => ({
                              ...current,
                              [bucket.name]: notificationRules.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, target: event.target.value } : item
                              )
                            }))
                          }
                          placeholder="目标"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={rule.prefix ?? ''}
                          onChange={(event) =>
                            setNotificationDrafts((current) => ({
                              ...current,
                              [bucket.name]: notificationRules.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, prefix: event.target.value } : item
                              )
                            }))
                          }
                          placeholder="prefix"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <input
                          value={rule.suffix ?? ''}
                          onChange={(event) =>
                            setNotificationDrafts((current) => ({
                              ...current,
                              [bucket.name]: notificationRules.map((item, itemIndex) =>
                                itemIndex === index ? { ...item, suffix: event.target.value } : item
                              )
                            }))
                          }
                          placeholder="suffix"
                          className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                        />
                        <div className="flex items-center justify-between gap-2">
                          <label className="flex items-center gap-1 text-xs text-slate-300">
                            <input
                              type="checkbox"
                              checked={rule.enabled}
                              onChange={(event) =>
                                setNotificationDrafts((current) => ({
                                  ...current,
                                  [bucket.name]: notificationRules.map((item, itemIndex) =>
                                    itemIndex === index ? { ...item, enabled: event.target.checked } : item
                                  )
                                }))
                              }
                            />
                            启用
                          </label>
                          <button
                            className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10"
                            onClick={() =>
                              setNotificationDrafts((current) => ({
                                ...current,
                                [bucket.name]: notificationRules.filter((_, itemIndex) => itemIndex !== index)
                              }))
                            }
                          >
                            删除
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <div className="mt-3 grid gap-2 rounded-md border border-white/10 p-2 md:grid-cols-6">
                  <input
                    value={newRule.id}
                    onChange={(event) =>
                      setNewRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newRule, id: event.target.value }
                      }))
                    }
                    placeholder="规则 ID"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newRule.event}
                    onChange={(event) =>
                      setNewRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newRule, event: event.target.value }
                      }))
                    }
                    placeholder="事件"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newRule.target}
                    onChange={(event) =>
                      setNewRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newRule, target: event.target.value }
                      }))
                    }
                    placeholder="目标"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newRule.prefix ?? ''}
                    onChange={(event) =>
                      setNewRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newRule, prefix: event.target.value }
                      }))
                    }
                    placeholder="prefix"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <input
                    value={newRule.suffix ?? ''}
                    onChange={(event) =>
                      setNewRuleDrafts((current) => ({
                        ...current,
                        [bucket.name]: { ...newRule, suffix: event.target.value }
                      }))
                    }
                    placeholder="suffix"
                    className="h-9 rounded-md border border-white/15 bg-ink-900 px-2 text-xs text-slate-100"
                  />
                  <div className="flex items-center justify-between gap-2">
                    <label className="flex items-center gap-1 text-xs text-slate-300">
                      <input
                        type="checkbox"
                        checked={newRule.enabled}
                        onChange={(event) =>
                          setNewRuleDrafts((current) => ({
                            ...current,
                            [bucket.name]: { ...newRule, enabled: event.target.checked }
                          }))
                        }
                      />
                      启用
                    </label>
                    <button
                      className="rounded-md border border-white/15 px-2 py-1 text-xs text-slate-200 hover:bg-white/5"
                      onClick={() => {
                        const normalized = normalizeRule(newRule);
                        if (!normalized.id || !normalized.event || !normalized.target) {
                          setError('通知规则的 ID、事件、目标不能为空');
                          return;
                        }
                        if (notificationRules.some((rule) => rule.id === normalized.id)) {
                          setError(`通知规则 ID ${normalized.id} 已存在`);
                          return;
                        }
                        setError('');
                        setNotificationDrafts((current) => ({
                          ...current,
                          [bucket.name]: [...notificationRules, normalized]
                        }));
                        setNewRuleDrafts((current) => ({
                          ...current,
                          [bucket.name]: defaultNotificationRule()
                        }));
                      }}
                    >
                      新增
                    </button>
                  </div>
                </div>

                <div className="mt-3">
                  <button
                    className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                    disabled={savingKey === `${bucket.name}:notifications`}
                    onClick={async () => {
                      setSavingKey(`${bucket.name}:notifications`);
                      setError('');
                      setMessage('');
                      try {
                        const payload = notificationRules.map(normalizeRule);
                        await bucketService.updateNotifications(client, bucket.name, payload);
                        setMessage(`桶 ${bucket.name} 的通知规则已更新`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '更新通知规则失败');
                      } finally {
                        setSavingKey('');
                      }
                    }}
                  >
                    {savingKey === `${bucket.name}:notifications` ? '保存中...' : '保存通知规则'}
                  </button>
                </div>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
