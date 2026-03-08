import { useEffect, useMemo, useState } from 'react';
import { toBilingualNotice, toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { alertService, jobsService, systemService } from '../api/services';
import { StatCard } from '../components/StatCard';
import type {
  AsyncJobSummary,
  AlertChannel,
  AlertEscalationPolicy,
  AlertHistoryEntry,
  AlertRule,
  AlertSilence,
  SystemMetricsSummary
} from '../types';

type AlertsPageProps = {
  client: ApiClient;
};

type ChannelDraft = {
  name: string;
  kind: string;
  endpoint: string;
  enabled: boolean;
};

type RuleDraft = {
  name: string;
  metric: string;
  condition: string;
  threshold: number;
  window_minutes: number;
  severity: string;
  enabled: boolean;
  channels: string[];
};

type EscalationDraft = {
  name: string;
  severity: string;
  wait_minutes: number;
  channels: string[];
  enabled: boolean;
};

type HistoryFilters = {
  severity: string;
  status: string;
  source: string;
  rule_id: string;
  limit: number;
};

function defaultRuleDraft(channelIds: string[]): RuleDraft {
  return {
    name: '',
    metric: 'cluster.capacity.used_ratio',
    condition: '>=',
    threshold: 0.85,
    window_minutes: 5,
    severity: 'warning',
    enabled: true,
    channels: channelIds.slice(0, 1)
  };
}

function defaultEscalationDraft(channelIds: string[]): EscalationDraft {
  return {
    name: '',
    severity: 'warning',
    wait_minutes: 15,
    channels: channelIds.slice(0, 1),
    enabled: true
  };
}

function channelStatusText(status: string) {
  if (status === 'healthy') return '健康';
  if (status === 'degraded') return '异常';
  if (status === 'paused') return '停用';
  return status;
}

function severityText(severity: string) {
  if (severity === 'critical') return '严重';
  if (severity === 'warning') return '警告';
  if (severity === 'info') return '提示';
  return severity;
}

function historyStatusText(status: string) {
  if (status === 'firing') return '触发中';
  if (status === 'acknowledged') return '已确认';
  if (status === 'resolved') return '已恢复';
  if (status === 'suppressed') return '已静默';
  if (status === 'test') return '测试';
  return status;
}

function toDateTimeLocalValue(iso?: string | null) {
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`;
}

function toIsoFromDateTimeLocal(value: string) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toISOString();
}

function toggleId(ids: string[], id: string, checked: boolean) {
  if (checked) {
    if (ids.includes(id)) return ids;
    return [...ids, id];
  }
  return ids.filter((item) => item !== id);
}

export function AlertsPage({ client }: AlertsPageProps) {
  const [channels, setChannels] = useState<AlertChannel[]>([]);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [silences, setSilences] = useState<AlertSilence[]>([]);
  const [escalations, setEscalations] = useState<AlertEscalationPolicy[]>([]);
  const [history, setHistory] = useState<AlertHistoryEntry[]>([]);
  const [summary, setSummary] = useState<SystemMetricsSummary | null>(null);
  const [notificationSummary, setNotificationSummary] = useState<AsyncJobSummary | null>(null);

  const [channelDrafts, setChannelDrafts] = useState<Record<string, ChannelDraft>>({});
  const [ruleDrafts, setRuleDrafts] = useState<Record<string, RuleDraft>>({});
  const [escalationDrafts, setEscalationDrafts] = useState<Record<string, EscalationDraft>>({});

  const [creatingChannel, setCreatingChannel] = useState(false);
  const [creatingRule, setCreatingRule] = useState(false);
  const [creatingSilence, setCreatingSilence] = useState(false);
  const [creatingEscalation, setCreatingEscalation] = useState(false);
  const [savingKey, setSavingKey] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const [newChannel, setNewChannel] = useState<ChannelDraft>({
    name: '',
    kind: 'webhook',
    endpoint: '',
    enabled: true
  });
  const [newRule, setNewRule] = useState<RuleDraft>(defaultRuleDraft([]));
  const [newEscalation, setNewEscalation] = useState<EscalationDraft>(defaultEscalationDraft([]));
  const [newSilence, setNewSilence] = useState({
    name: '',
    reason: '',
    rule_ids: [] as string[],
    starts_at: toDateTimeLocalValue(new Date(Date.now() - 5 * 60 * 1000).toISOString()),
    ends_at: toDateTimeLocalValue(new Date(Date.now() + 60 * 60 * 1000).toISOString()),
    enabled: true
  });

  const [historyFilters, setHistoryFilters] = useState<HistoryFilters>({
    severity: '',
    status: '',
    source: '',
    rule_id: '',
    limit: 200
  });

  const channelNames = useMemo(
    () => Object.fromEntries(channels.map((channel) => [channel.id, channel.name])),
    [channels]
  );

  const ruleNames = useMemo(
    () => Object.fromEntries(rules.map((rule) => [rule.id, rule.name])),
    [rules]
  );

  async function reloadConfig() {
    const [channelRows, ruleRows, silenceRows, escalationRows] = await Promise.all([
      alertService.channels(client),
      alertService.rules(client),
      alertService.silences(client),
      alertService.escalations(client)
    ]);

    setChannels(channelRows);
    setRules(ruleRows);
    setSilences(silenceRows);
    setEscalations(escalationRows);

    setChannelDrafts(
      Object.fromEntries(
        channelRows.map((channel) => [
          channel.id,
          {
            name: channel.name,
            kind: channel.kind,
            endpoint: channel.endpoint,
            enabled: channel.enabled
          }
        ])
      )
    );

    setRuleDrafts(
      Object.fromEntries(
        ruleRows.map((rule) => [
          rule.id,
          {
            name: rule.name,
            metric: rule.metric,
            condition: rule.condition,
            threshold: rule.threshold,
            window_minutes: rule.window_minutes,
            severity: rule.severity,
            enabled: rule.enabled,
            channels: [...rule.channels]
          }
        ])
      )
    );

    setEscalationDrafts(
      Object.fromEntries(
        escalationRows.map((policy) => [
          policy.id,
          {
            name: policy.name,
            severity: policy.severity,
            wait_minutes: policy.wait_minutes,
            channels: [...policy.channels],
            enabled: policy.enabled
          }
        ])
      )
    );

    setNewRule((current) => {
      if (current.channels.length > 0 || channelRows.length === 0) return current;
      return { ...current, channels: [channelRows[0].id] };
    });

    setNewEscalation((current) => {
      if (current.channels.length > 0 || channelRows.length === 0) return current;
      return { ...current, channels: [channelRows[0].id] };
    });

    setNewSilence((current) => {
      if (current.rule_ids.length > 0 || ruleRows.length === 0) return current;
      return { ...current, rule_ids: [ruleRows[0].id] };
    });
  }

  async function reloadHistory(filters = historyFilters) {
    const rows = await alertService.history(client, {
      limit: filters.limit,
      severity: filters.severity || undefined,
      status: filters.status || undefined,
      source: filters.source || undefined,
      rule_id: filters.rule_id || undefined
    });
    setHistory(rows);
  }

  async function reloadAll() {
    const [metricsSummary, asyncNotificationSummary] = await Promise.all([
      systemService.metricsSummary(client),
      jobsService.asyncJobsSummary(client, { kind: 'notification' })
    ]);
    setSummary(metricsSummary);
    setNotificationSummary(asyncNotificationSummary);
    await Promise.all([reloadConfig(), reloadHistory()]);
  }

  useEffect(() => {
    reloadAll().catch((requestError) => {
      setError(requestError instanceof Error ? requestError.message : '加载告警配置失败');
    });
  }, [client]);

  const sortedChannels = useMemo(
    () => [...channels].sort((left, right) => left.name.localeCompare(right.name)),
    [channels]
  );

  const sortedRules = useMemo(
    () => [...rules].sort((left, right) => left.name.localeCompare(right.name)),
    [rules]
  );

  const sortedSilences = useMemo(
    () => [...silences].sort((left, right) => right.starts_at.localeCompare(left.starts_at)),
    [silences]
  );

  const sortedEscalations = useMemo(
    () => [...escalations].sort((left, right) => left.name.localeCompare(right.name)),
    [escalations]
  );

  return (
    <section className="space-y-4">
      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h1 className="font-heading text-2xl text-white">告警中心</h1>
        <p className="mt-1 text-sm text-slate-300">
          告警规则、通知渠道、静默窗口、升级策略与触发历史可视化管理。
        </p>
        {error ? <p className="mt-3 text-sm text-rose-400">{toBilingualPrompt(error)}</p> : null}
        {message ? <p className="mt-3 text-sm text-signal-500">{toBilingualNotice(message)}</p> : null}

        <div className="mt-4 grid gap-4 md:grid-cols-4">
          <StatCard
            label="告警规则"
            value={summary ? String(summary.alerts.rules_total) : '...'}
            helper={summary ? `触发中 ${summary.alerts.firing_alerts}` : '统一告警摘要'}
          />
          <StatCard
            label="通知渠道"
            value={summary ? `${summary.alerts.channels_healthy}/${summary.alerts.channels_enabled}` : '...'}
            helper="健康 / 已启用"
          />
          <StatCard
            label="异步投递"
            value={notificationSummary ? String(notificationSummary.total) : '...'}
            helper={
              notificationSummary
                ? `待处理 ${notificationSummary.pending} / 失败 ${notificationSummary.failed}`
                : '统一通知任务口径'
            }
          />
          <StatCard
            label="可重试"
            value={notificationSummary ? String(notificationSummary.retryable) : '...'}
            helper={
              notificationSummary
                ? `死信 ${notificationSummary.dead_letter} / 已完成 ${notificationSummary.completed}`
                : '异步投递重试'
            }
          />
        </div>
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="font-heading text-xl text-white">通知渠道</h2>
          <button
            className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
            onClick={async () => {
              setError('');
              try {
                await reloadConfig();
              } catch (requestError) {
                setError(requestError instanceof Error ? requestError.message : '刷新通知渠道失败');
              }
            }}
          >
            刷新
          </button>
        </div>

        <form
          className="mt-3 grid gap-2 rounded-lg border border-white/10 bg-black/10 p-3 md:grid-cols-5"
          onSubmit={async (event) => {
            event.preventDefault();
            setCreatingChannel(true);
            setError('');
            setMessage('');
            try {
              await alertService.createChannel(client, newChannel);
              setMessage(`通知渠道 ${newChannel.name} 创建成功`);
              setNewChannel({ name: '', kind: 'webhook', endpoint: '', enabled: true });
              await reloadConfig();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '创建通知渠道失败');
            } finally {
              setCreatingChannel(false);
            }
          }}
        >
          <input
            required
            value={newChannel.name}
            onChange={(event) => setNewChannel((current) => ({ ...current, name: event.target.value }))}
            placeholder="渠道名称"
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
          <select
            value={newChannel.kind}
            onChange={(event) => setNewChannel((current) => ({ ...current, kind: event.target.value }))}
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          >
            <option value="webhook">webhook</option>
            <option value="email">email</option>
            <option value="slack">slack</option>
            <option value="nats">nats</option>
          </select>
          <input
            required
            value={newChannel.endpoint}
            onChange={(event) => setNewChannel((current) => ({ ...current, endpoint: event.target.value }))}
            placeholder="endpoint"
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100 md:col-span-2"
          />
          <div className="flex items-center justify-between gap-2">
            <label className="flex items-center gap-2 text-xs text-slate-300">
              <input
                type="checkbox"
                checked={newChannel.enabled}
                onChange={(event) =>
                  setNewChannel((current) => ({ ...current, enabled: event.target.checked }))
                }
              />
              启用
            </label>
            <button
              type="submit"
              disabled={creatingChannel}
              className="h-10 rounded-md bg-signal-600 px-3 text-sm text-white disabled:opacity-60"
            >
              {creatingChannel ? '创建中...' : '新增渠道'}
            </button>
          </div>
        </form>

        <div className="mt-3 space-y-2">
          {sortedChannels.map((channel) => {
            const draft = channelDrafts[channel.id] ?? {
              name: channel.name,
              kind: channel.kind,
              endpoint: channel.endpoint,
              enabled: channel.enabled
            };
            return (
              <article key={channel.id} className="rounded-lg border border-white/10 bg-black/10 p-3">
                <div className="grid gap-2 md:grid-cols-6">
                  <input
                    value={draft.name}
                    onChange={(event) =>
                      setChannelDrafts((current) => ({
                        ...current,
                        [channel.id]: {
                          ...draft,
                          name: event.target.value
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  />
                  <select
                    value={draft.kind}
                    onChange={(event) =>
                      setChannelDrafts((current) => ({
                        ...current,
                        [channel.id]: {
                          ...draft,
                          kind: event.target.value
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  >
                    <option value="webhook">webhook</option>
                    <option value="email">email</option>
                    <option value="slack">slack</option>
                    <option value="nats">nats</option>
                  </select>
                  <input
                    value={draft.endpoint}
                    onChange={(event) =>
                      setChannelDrafts((current) => ({
                        ...current,
                        [channel.id]: {
                          ...draft,
                          endpoint: event.target.value
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100 md:col-span-2"
                  />
                  <label className="flex items-center gap-2 text-xs text-slate-300">
                    <input
                      type="checkbox"
                      checked={draft.enabled}
                      onChange={(event) =>
                        setChannelDrafts((current) => ({
                          ...current,
                          [channel.id]: {
                            ...draft,
                            enabled: event.target.checked
                          }
                        }))
                      }
                    />
                    启用
                  </label>
                  <div className="flex items-center justify-end gap-2">
                    <button
                      className="h-10 rounded-md border border-white/15 px-3 text-xs text-slate-100 hover:bg-white/5 disabled:opacity-60"
                      disabled={savingKey === `${channel.id}:save`}
                      onClick={async () => {
                        setSavingKey(`${channel.id}:save`);
                        setError('');
                        setMessage('');
                        try {
                          await alertService.updateChannel(client, channel.id, draft);
                          setMessage(`通知渠道 ${channel.name} 已更新`);
                          await reloadConfig();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '更新通知渠道失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      保存
                    </button>
                    <button
                      className="h-10 rounded-md border border-signal-500/40 px-3 text-xs text-signal-500 hover:bg-signal-500/10 disabled:opacity-60"
                      disabled={savingKey === `${channel.id}:test`}
                      onClick={async () => {
                        setSavingKey(`${channel.id}:test`);
                        setError('');
                        setMessage('');
                        try {
                          await alertService.testChannel(client, channel.id);
                          setMessage(`渠道 ${channel.name} 测试完成`);
                          await Promise.all([reloadConfig(), reloadHistory()]);
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '测试通知渠道失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      测试
                    </button>
                    <button
                      className="h-10 rounded-md border border-rose-500/40 px-3 text-xs text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                      disabled={savingKey === `${channel.id}:delete`}
                      onClick={async () => {
                        if (!window.confirm(`确认删除通知渠道 ${channel.name}？`)) return;
                        setSavingKey(`${channel.id}:delete`);
                        setError('');
                        setMessage('');
                        try {
                          await alertService.deleteChannel(client, channel.id);
                          setMessage(`通知渠道 ${channel.name} 已删除`);
                          await reloadConfig();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '删除通知渠道失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      删除
                    </button>
                  </div>
                </div>
                <p className="mt-2 text-xs text-slate-400">
                  ID: <span className="font-mono text-slate-300">{channel.id}</span> · 状态：
                  <span
                    className={`ml-1 ${
                      channel.status === 'healthy'
                        ? 'text-signal-500'
                        : channel.status === 'paused'
                          ? 'text-amber-300'
                          : 'text-rose-300'
                    }`}
                  >
                    {channelStatusText(channel.status)}
                  </span>
                  · 最近检查：{new Date(channel.last_checked_at).toLocaleString()}
                </p>
                {channel.error ? (
                  <p className="mt-1 text-xs text-rose-300">错误：{toBilingualPrompt(channel.error)}</p>
                ) : null}
              </article>
            );
          })}
        </div>
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h2 className="font-heading text-xl text-white">告警规则</h2>

        <form
          className="mt-3 grid gap-2 rounded-lg border border-white/10 bg-black/10 p-3 md:grid-cols-6"
          onSubmit={async (event) => {
            event.preventDefault();
            if (newRule.channels.length === 0) {
              setError('至少选择一个通知渠道');
              return;
            }
            setCreatingRule(true);
            setError('');
            setMessage('');
            try {
              await alertService.createRule(client, newRule);
              setMessage(`告警规则 ${newRule.name} 创建成功`);
              setNewRule(defaultRuleDraft(channels.map((channel) => channel.id)));
              await reloadConfig();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '创建告警规则失败');
            } finally {
              setCreatingRule(false);
            }
          }}
        >
          <input
            required
            value={newRule.name}
            onChange={(event) => setNewRule((current) => ({ ...current, name: event.target.value }))}
            placeholder="规则名称"
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
          <input
            required
            value={newRule.metric}
            onChange={(event) => setNewRule((current) => ({ ...current, metric: event.target.value }))}
            placeholder="metric"
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
          <select
            value={newRule.condition}
            onChange={(event) => setNewRule((current) => ({ ...current, condition: event.target.value }))}
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          >
            <option value=">">&gt;</option>
            <option value=">=">&gt;=</option>
            <option value="<">&lt;</option>
            <option value="<=">&lt;=</option>
            <option value="=">=</option>
            <option value="!=">!=</option>
          </select>
          <input
            type="number"
            step="0.01"
            value={newRule.threshold}
            onChange={(event) =>
              setNewRule((current) => ({ ...current, threshold: Number(event.target.value) }))
            }
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
          <input
            type="number"
            min={1}
            value={newRule.window_minutes}
            onChange={(event) =>
              setNewRule((current) => ({ ...current, window_minutes: Number(event.target.value) }))
            }
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
          <select
            value={newRule.severity}
            onChange={(event) => setNewRule((current) => ({ ...current, severity: event.target.value }))}
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          >
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>

          <div className="md:col-span-4 rounded-md border border-white/10 bg-ink-900/40 p-2">
            <p className="text-xs text-slate-400">通知渠道</p>
            <div className="mt-2 flex flex-wrap gap-3">
              {channels.map((channel) => (
                <label key={channel.id} className="flex items-center gap-2 text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={newRule.channels.includes(channel.id)}
                    onChange={(event) =>
                      setNewRule((current) => ({
                        ...current,
                        channels: toggleId(current.channels, channel.id, event.target.checked)
                      }))
                    }
                  />
                  {channel.name}
                </label>
              ))}
            </div>
          </div>

          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={newRule.enabled}
              onChange={(event) => setNewRule((current) => ({ ...current, enabled: event.target.checked }))}
            />
            启用规则
          </label>

          <div className="md:col-span-6">
            <button
              type="submit"
              disabled={creatingRule}
              className="h-10 rounded-md bg-signal-600 px-4 text-sm text-white disabled:opacity-60"
            >
              {creatingRule ? '创建中...' : '新增规则'}
            </button>
          </div>
        </form>

        <div className="mt-3 space-y-2">
          {sortedRules.map((rule) => {
            const draft =
              ruleDrafts[rule.id] ?? {
                name: rule.name,
                metric: rule.metric,
                condition: rule.condition,
                threshold: rule.threshold,
                window_minutes: rule.window_minutes,
                severity: rule.severity,
                enabled: rule.enabled,
                channels: [...rule.channels]
              };

            return (
              <article key={rule.id} className="rounded-lg border border-white/10 bg-black/10 p-3">
                <div className="grid gap-2 md:grid-cols-7">
                  <input
                    value={draft.name}
                    onChange={(event) =>
                      setRuleDrafts((current) => ({
                        ...current,
                        [rule.id]: {
                          ...draft,
                          name: event.target.value
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  />
                  <input
                    value={draft.metric}
                    onChange={(event) =>
                      setRuleDrafts((current) => ({
                        ...current,
                        [rule.id]: {
                          ...draft,
                          metric: event.target.value
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  />
                  <select
                    value={draft.condition}
                    onChange={(event) =>
                      setRuleDrafts((current) => ({
                        ...current,
                        [rule.id]: {
                          ...draft,
                          condition: event.target.value
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  >
                    <option value=">">&gt;</option>
                    <option value=">=">&gt;=</option>
                    <option value="<">&lt;</option>
                    <option value="<=">&lt;=</option>
                    <option value="=">=</option>
                    <option value="!=">!=</option>
                  </select>
                  <input
                    type="number"
                    step="0.01"
                    value={draft.threshold}
                    onChange={(event) =>
                      setRuleDrafts((current) => ({
                        ...current,
                        [rule.id]: {
                          ...draft,
                          threshold: Number(event.target.value)
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  />
                  <input
                    type="number"
                    min={1}
                    value={draft.window_minutes}
                    onChange={(event) =>
                      setRuleDrafts((current) => ({
                        ...current,
                        [rule.id]: {
                          ...draft,
                          window_minutes: Number(event.target.value)
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  />
                  <select
                    value={draft.severity}
                    onChange={(event) =>
                      setRuleDrafts((current) => ({
                        ...current,
                        [rule.id]: {
                          ...draft,
                          severity: event.target.value
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  >
                    <option value="info">info</option>
                    <option value="warning">warning</option>
                    <option value="critical">critical</option>
                  </select>
                  <label className="flex items-center gap-2 text-xs text-slate-300">
                    <input
                      type="checkbox"
                      checked={draft.enabled}
                      onChange={(event) =>
                        setRuleDrafts((current) => ({
                          ...current,
                          [rule.id]: {
                            ...draft,
                            enabled: event.target.checked
                          }
                        }))
                      }
                    />
                    启用
                  </label>
                </div>

                <div className="mt-2 rounded-md border border-white/10 bg-ink-900/40 p-2">
                  <p className="text-xs text-slate-400">通知渠道</p>
                  <div className="mt-2 flex flex-wrap gap-3">
                    {channels.map((channel) => (
                      <label key={`${rule.id}:${channel.id}`} className="flex items-center gap-2 text-xs text-slate-300">
                        <input
                          type="checkbox"
                          checked={draft.channels.includes(channel.id)}
                          onChange={(event) =>
                            setRuleDrafts((current) => ({
                              ...current,
                              [rule.id]: {
                                ...draft,
                                channels: toggleId(draft.channels, channel.id, event.target.checked)
                              }
                            }))
                          }
                        />
                        {channel.name}
                      </label>
                    ))}
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
                  <p className="text-xs text-slate-400">
                    ID: <span className="font-mono text-slate-300">{rule.id}</span> · 严重级别：
                    <span
                      className={`ml-1 ${
                        rule.severity === 'critical'
                          ? 'text-rose-300'
                          : rule.severity === 'warning'
                            ? 'text-amber-300'
                            : 'text-signal-500'
                      }`}
                    >
                      {severityText(rule.severity)}
                    </span>
                    {rule.last_triggered_at
                      ? ` · 最近触发：${new Date(rule.last_triggered_at).toLocaleString()}`
                      : ' · 最近触发：暂无'}
                    {rule.channels.length > 0
                      ? ` · 目标：${rule.channels.map((id) => channelNames[id] ?? id).join(', ')}`
                      : ' · 目标：无'}
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      className="h-10 rounded-md border border-white/15 px-3 text-xs text-slate-100 hover:bg-white/5 disabled:opacity-60"
                      disabled={savingKey === `${rule.id}:save`}
                      onClick={async () => {
                        if (draft.channels.length === 0) {
                          setError('规则至少需要一个通知渠道');
                          return;
                        }
                        setSavingKey(`${rule.id}:save`);
                        setError('');
                        setMessage('');
                        try {
                          await alertService.updateRule(client, rule.id, draft);
                          setMessage(`告警规则 ${rule.name} 已更新`);
                          await reloadConfig();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '更新告警规则失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      保存
                    </button>
                    <button
                      className="h-10 rounded-md border border-signal-500/40 px-3 text-xs text-signal-500 hover:bg-signal-500/10 disabled:opacity-60"
                      disabled={savingKey === `${rule.id}:simulate`}
                      onClick={async () => {
                        setSavingKey(`${rule.id}:simulate`);
                        setError('');
                        setMessage('');
                        try {
                          const entry = await alertService.simulateRule(client, rule.id);
                          setMessage(`规则 ${rule.name} 已完成实时评估（${historyStatusText(entry.status)}）`);
                          await Promise.all([reloadConfig(), reloadHistory()]);
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '规则评估失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      立即评估
                    </button>
                    <button
                      className="h-10 rounded-md border border-rose-500/40 px-3 text-xs text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                      disabled={savingKey === `${rule.id}:delete`}
                      onClick={async () => {
                        if (!window.confirm(`确认删除告警规则 ${rule.name}？`)) return;
                        setSavingKey(`${rule.id}:delete`);
                        setError('');
                        setMessage('');
                        try {
                          await alertService.deleteRule(client, rule.id);
                          setMessage(`告警规则 ${rule.name} 已删除`);
                          await reloadConfig();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '删除告警规则失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      删除
                    </button>
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h2 className="font-heading text-xl text-white">静默窗口</h2>
        <form
          className="mt-3 grid gap-2 rounded-lg border border-white/10 bg-black/10 p-3 md:grid-cols-6"
          onSubmit={async (event) => {
            event.preventDefault();
            if (newSilence.rule_ids.length === 0) {
              setError('静默窗口至少选择一个规则');
              return;
            }
            const startsAt = toIsoFromDateTimeLocal(newSilence.starts_at);
            const endsAt = toIsoFromDateTimeLocal(newSilence.ends_at);
            if (!startsAt || !endsAt) {
              setError('请填写有效的开始和结束时间');
              return;
            }
            setCreatingSilence(true);
            setError('');
            setMessage('');
            try {
              await alertService.createSilence(client, {
                name: newSilence.name,
                reason: newSilence.reason,
                rule_ids: newSilence.rule_ids,
                starts_at: startsAt,
                ends_at: endsAt,
                enabled: newSilence.enabled
              });
              setMessage(`静默窗口 ${newSilence.name} 创建成功`);
              setNewSilence((current) => ({
                ...current,
                name: '',
                reason: '',
                rule_ids: rules[0] ? [rules[0].id] : []
              }));
              await reloadConfig();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '创建静默窗口失败');
            } finally {
              setCreatingSilence(false);
            }
          }}
        >
          <input
            required
            value={newSilence.name}
            onChange={(event) => setNewSilence((current) => ({ ...current, name: event.target.value }))}
            placeholder="静默名称"
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
          <input
            required
            value={newSilence.reason}
            onChange={(event) => setNewSilence((current) => ({ ...current, reason: event.target.value }))}
            placeholder="静默原因"
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
          <label className="text-xs text-slate-400">
            开始
            <input
              type="datetime-local"
              value={newSilence.starts_at}
              onChange={(event) =>
                setNewSilence((current) => ({ ...current, starts_at: event.target.value }))
              }
              className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
            />
          </label>
          <label className="text-xs text-slate-400">
            结束
            <input
              type="datetime-local"
              value={newSilence.ends_at}
              onChange={(event) =>
                setNewSilence((current) => ({ ...current, ends_at: event.target.value }))
              }
              className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
            />
          </label>
          <label className="flex items-center gap-2 text-xs text-slate-300 md:mt-6">
            <input
              type="checkbox"
              checked={newSilence.enabled}
              onChange={(event) => setNewSilence((current) => ({ ...current, enabled: event.target.checked }))}
            />
            启用静默
          </label>
          <button
            type="submit"
            disabled={creatingSilence}
            className="h-10 rounded-md bg-signal-600 px-3 text-sm text-white disabled:opacity-60 md:mt-6"
          >
            {creatingSilence ? '创建中...' : '新增静默'}
          </button>

          <div className="md:col-span-6 rounded-md border border-white/10 bg-ink-900/40 p-2">
            <p className="text-xs text-slate-400">静默规则范围</p>
            <div className="mt-2 flex flex-wrap gap-3">
              {rules.map((rule) => (
                <label key={`silence:${rule.id}`} className="flex items-center gap-2 text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={newSilence.rule_ids.includes(rule.id)}
                    onChange={(event) =>
                      setNewSilence((current) => ({
                        ...current,
                        rule_ids: toggleId(current.rule_ids, rule.id, event.target.checked)
                      }))
                    }
                  />
                  {rule.name}
                </label>
              ))}
            </div>
          </div>
        </form>

        <div className="mt-3 space-y-2">
          {sortedSilences.length === 0 ? (
            <p className="rounded-md border border-white/10 bg-black/10 p-3 text-xs text-slate-400">
              暂无静默窗口。
            </p>
          ) : (
            sortedSilences.map((silence) => (
              <article key={silence.id} className="rounded-lg border border-white/10 bg-black/10 p-3">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-sm font-medium text-white">{silence.name}</p>
                  <button
                    className="h-9 rounded-md border border-rose-500/40 px-3 text-xs text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                    disabled={savingKey === `${silence.id}:delete`}
                    onClick={async () => {
                      if (!window.confirm(`确认删除静默窗口 ${silence.name}？`)) return;
                      setSavingKey(`${silence.id}:delete`);
                      setError('');
                      setMessage('');
                      try {
                        await alertService.deleteSilence(client, silence.id);
                        setMessage(`静默窗口 ${silence.name} 已删除`);
                        await reloadConfig();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '删除静默窗口失败');
                      } finally {
                        setSavingKey('');
                      }
                    }}
                  >
                    删除
                  </button>
                </div>
                <p className="mt-1 text-xs text-slate-400">
                  范围：{silence.rule_ids.map((ruleId) => ruleNames[ruleId] ?? ruleId).join(', ')}
                </p>
                <p className="mt-1 text-xs text-slate-400">
                  时间：{new Date(silence.starts_at).toLocaleString()} -{' '}
                  {new Date(silence.ends_at).toLocaleString()}
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  创建人：{silence.created_by} · 原因：{silence.reason} · {silence.enabled ? '已启用' : '未启用'}
                </p>
              </article>
            ))
          )}
        </div>
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h2 className="font-heading text-xl text-white">升级策略</h2>
        <form
          className="mt-3 grid gap-2 rounded-lg border border-white/10 bg-black/10 p-3 md:grid-cols-6"
          onSubmit={async (event) => {
            event.preventDefault();
            if (newEscalation.channels.length === 0) {
              setError('升级策略至少选择一个通知渠道');
              return;
            }
            setCreatingEscalation(true);
            setError('');
            setMessage('');
            try {
              await alertService.createEscalation(client, newEscalation);
              setMessage(`升级策略 ${newEscalation.name} 创建成功`);
              setNewEscalation(defaultEscalationDraft(channels.map((channel) => channel.id)));
              await reloadConfig();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '创建升级策略失败');
            } finally {
              setCreatingEscalation(false);
            }
          }}
        >
          <input
            required
            value={newEscalation.name}
            onChange={(event) =>
              setNewEscalation((current) => ({ ...current, name: event.target.value }))
            }
            placeholder="策略名称"
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
          <select
            value={newEscalation.severity}
            onChange={(event) =>
              setNewEscalation((current) => ({ ...current, severity: event.target.value }))
            }
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          >
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>
          <input
            type="number"
            min={1}
            value={newEscalation.wait_minutes}
            onChange={(event) =>
              setNewEscalation((current) => ({ ...current, wait_minutes: Number(event.target.value) }))
            }
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
          <label className="flex items-center gap-2 text-xs text-slate-300 md:mt-2">
            <input
              type="checkbox"
              checked={newEscalation.enabled}
              onChange={(event) =>
                setNewEscalation((current) => ({ ...current, enabled: event.target.checked }))
              }
            />
            启用策略
          </label>
          <div className="md:col-span-2">
            <button
              type="submit"
              disabled={creatingEscalation}
              className="h-10 rounded-md bg-signal-600 px-3 text-sm text-white disabled:opacity-60"
            >
              {creatingEscalation ? '创建中...' : '新增升级策略'}
            </button>
          </div>

          <div className="md:col-span-6 rounded-md border border-white/10 bg-ink-900/40 p-2">
            <p className="text-xs text-slate-400">升级通知渠道</p>
            <div className="mt-2 flex flex-wrap gap-3">
              {channels.map((channel) => (
                <label key={`esc-new:${channel.id}`} className="flex items-center gap-2 text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={newEscalation.channels.includes(channel.id)}
                    onChange={(event) =>
                      setNewEscalation((current) => ({
                        ...current,
                        channels: toggleId(current.channels, channel.id, event.target.checked)
                      }))
                    }
                  />
                  {channel.name}
                </label>
              ))}
            </div>
          </div>
        </form>

        <div className="mt-3 space-y-2">
          {sortedEscalations.map((policy) => {
            const draft = escalationDrafts[policy.id] ?? {
              name: policy.name,
              severity: policy.severity,
              wait_minutes: policy.wait_minutes,
              channels: [...policy.channels],
              enabled: policy.enabled
            };

            return (
              <article key={policy.id} className="rounded-lg border border-white/10 bg-black/10 p-3">
                <div className="grid gap-2 md:grid-cols-5">
                  <input
                    value={draft.name}
                    onChange={(event) =>
                      setEscalationDrafts((current) => ({
                        ...current,
                        [policy.id]: {
                          ...draft,
                          name: event.target.value
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  />
                  <select
                    value={draft.severity}
                    onChange={(event) =>
                      setEscalationDrafts((current) => ({
                        ...current,
                        [policy.id]: {
                          ...draft,
                          severity: event.target.value
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  >
                    <option value="info">info</option>
                    <option value="warning">warning</option>
                    <option value="critical">critical</option>
                  </select>
                  <input
                    type="number"
                    min={1}
                    value={draft.wait_minutes}
                    onChange={(event) =>
                      setEscalationDrafts((current) => ({
                        ...current,
                        [policy.id]: {
                          ...draft,
                          wait_minutes: Number(event.target.value)
                        }
                      }))
                    }
                    className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                  />
                  <label className="flex items-center gap-2 text-xs text-slate-300">
                    <input
                      type="checkbox"
                      checked={draft.enabled}
                      onChange={(event) =>
                        setEscalationDrafts((current) => ({
                          ...current,
                          [policy.id]: {
                            ...draft,
                            enabled: event.target.checked
                          }
                        }))
                      }
                    />
                    启用
                  </label>
                  <div className="flex items-center justify-end gap-2">
                    <button
                      className="h-10 rounded-md border border-white/15 px-3 text-xs text-slate-100 hover:bg-white/5 disabled:opacity-60"
                      disabled={savingKey === `${policy.id}:save`}
                      onClick={async () => {
                        if (draft.channels.length === 0) {
                          setError('升级策略至少需要一个通知渠道');
                          return;
                        }
                        setSavingKey(`${policy.id}:save`);
                        setError('');
                        setMessage('');
                        try {
                          await alertService.updateEscalation(client, policy.id, draft);
                          setMessage(`升级策略 ${policy.name} 已更新`);
                          await reloadConfig();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '更新升级策略失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      保存
                    </button>
                    <button
                      className="h-10 rounded-md border border-rose-500/40 px-3 text-xs text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                      disabled={savingKey === `${policy.id}:delete`}
                      onClick={async () => {
                        if (!window.confirm(`确认删除升级策略 ${policy.name}？`)) return;
                        setSavingKey(`${policy.id}:delete`);
                        setError('');
                        setMessage('');
                        try {
                          await alertService.deleteEscalation(client, policy.id);
                          setMessage(`升级策略 ${policy.name} 已删除`);
                          await reloadConfig();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '删除升级策略失败');
                        } finally {
                          setSavingKey('');
                        }
                      }}
                    >
                      删除
                    </button>
                  </div>
                </div>

                <div className="mt-2 rounded-md border border-white/10 bg-ink-900/40 p-2">
                  <p className="text-xs text-slate-400">升级通知渠道</p>
                  <div className="mt-2 flex flex-wrap gap-3">
                    {channels.map((channel) => (
                      <label
                        key={`esc:${policy.id}:${channel.id}`}
                        className="flex items-center gap-2 text-xs text-slate-300"
                      >
                        <input
                          type="checkbox"
                          checked={draft.channels.includes(channel.id)}
                          onChange={(event) =>
                            setEscalationDrafts((current) => ({
                              ...current,
                              [policy.id]: {
                                ...draft,
                                channels: toggleId(draft.channels, channel.id, event.target.checked)
                              }
                            }))
                          }
                        />
                        {channel.name}
                      </label>
                    ))}
                  </div>
                </div>

                <p className="mt-2 text-xs text-slate-400">
                  ID: <span className="font-mono text-slate-300">{policy.id}</span> · 严重级别：
                  {severityText(policy.severity)} · 升级等待：{policy.wait_minutes} 分钟
                </p>
              </article>
            );
          })}
        </div>
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="font-heading text-xl text-white">触发历史</h2>
          <button
            className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
            onClick={async () => {
              setError('');
              try {
                await reloadHistory();
              } catch (requestError) {
                setError(requestError instanceof Error ? requestError.message : '刷新触发历史失败');
              }
            }}
          >
            刷新
          </button>
        </div>

        <div className="mt-3 grid gap-2 rounded-lg border border-white/10 bg-black/10 p-3 md:grid-cols-5">
          <select
            value={historyFilters.severity}
            onChange={(event) =>
              setHistoryFilters((current) => ({ ...current, severity: event.target.value }))
            }
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          >
            <option value="">全部严重级别</option>
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>
          <select
            value={historyFilters.status}
            onChange={(event) => setHistoryFilters((current) => ({ ...current, status: event.target.value }))}
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          >
            <option value="">全部状态</option>
            <option value="firing">firing</option>
            <option value="acknowledged">acknowledged</option>
            <option value="resolved">resolved</option>
            <option value="suppressed">suppressed</option>
            <option value="test">test</option>
          </select>
          <input
            value={historyFilters.source}
            onChange={(event) => setHistoryFilters((current) => ({ ...current, source: event.target.value }))}
            placeholder="来源"
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
          <select
            value={historyFilters.rule_id}
            onChange={(event) => setHistoryFilters((current) => ({ ...current, rule_id: event.target.value }))}
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          >
            <option value="">全部规则</option>
            {rules.map((rule) => (
              <option key={rule.id} value={rule.id}>
                {rule.name}
              </option>
            ))}
          </select>
          <select
            value={historyFilters.limit}
            onChange={(event) =>
              setHistoryFilters((current) => ({ ...current, limit: Number(event.target.value) }))
            }
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          >
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={200}>200</option>
            <option value={500}>500</option>
          </select>

          <div className="md:col-span-5 flex gap-2">
            <button
              className="h-10 rounded-md bg-signal-600 px-4 text-sm text-white"
              onClick={async () => {
                setError('');
                try {
                  await reloadHistory(historyFilters);
                } catch (requestError) {
                  setError(requestError instanceof Error ? requestError.message : '检索触发历史失败');
                }
              }}
            >
              应用筛选
            </button>
            <button
              className="h-10 rounded-md border border-white/15 px-4 text-sm text-slate-100 hover:bg-white/5"
              onClick={async () => {
                const reset: HistoryFilters = {
                  severity: '',
                  status: '',
                  source: '',
                  rule_id: '',
                  limit: 200
                };
                setHistoryFilters(reset);
                setError('');
                try {
                  await reloadHistory(reset);
                } catch (requestError) {
                  setError(requestError instanceof Error ? requestError.message : '重置筛选失败');
                }
              }}
            >
              清空筛选
            </button>
          </div>
        </div>

        <ul className="mt-3 max-h-[28rem] space-y-2 overflow-auto pr-1">
          {history.map((entry) => (
            <li key={entry.id} className="rounded-lg border border-white/10 bg-black/10 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-sm font-medium text-white">{entry.rule_name ?? '系统事件'}</p>
                <div className="flex items-center gap-2 text-xs">
                  <span
                    className={`rounded-full px-2 py-1 ${
                      entry.severity === 'critical'
                        ? 'bg-rose-500/20 text-rose-300'
                        : entry.severity === 'warning'
                          ? 'bg-amber-500/20 text-amber-300'
                          : 'bg-signal-500/20 text-signal-500'
                    }`}
                  >
                    {severityText(entry.severity)}
                  </span>
                  <span className="text-slate-400">{historyStatusText(entry.status)}</span>
                </div>
              </div>
              <p className="mt-1 text-sm text-slate-200">{entry.message}</p>
              <p className="mt-1 text-xs text-slate-400">
                来源：{entry.source} · 时间：{new Date(entry.triggered_at).toLocaleString()}
                {entry.rule_id ? ` · RuleID: ${entry.rule_id}` : ''}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                认领：{entry.assignee ?? '未认领'}
                {entry.claimed_at ? `（${new Date(entry.claimed_at).toLocaleString()}）` : ''}
                {' · '}
                确认：{entry.acknowledged_by ?? '未确认'}
                {entry.acknowledged_at ? `（${new Date(entry.acknowledged_at).toLocaleString()}）` : ''}
                {' · '}
                恢复：{entry.resolved_by ?? '未恢复'}
                {entry.resolved_at ? `（${new Date(entry.resolved_at).toLocaleString()}）` : ''}
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                <button
                  className="h-9 rounded-md border border-white/15 px-3 text-xs text-slate-100 hover:bg-white/5 disabled:opacity-60"
                  disabled={savingKey === `${entry.id}:claim`}
                  onClick={async () => {
                    setSavingKey(`${entry.id}:claim`);
                    setError('');
                    setMessage('');
                    try {
                      await alertService.claimHistory(client, entry.id);
                      setMessage(`告警事件 ${entry.id} 已认领`);
                      await reloadHistory(historyFilters);
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '认领告警失败');
                    } finally {
                      setSavingKey('');
                    }
                  }}
                >
                  认领
                </button>
                <button
                  className="h-9 rounded-md border border-signal-500/40 px-3 text-xs text-signal-500 hover:bg-signal-500/10 disabled:opacity-60"
                  disabled={savingKey === `${entry.id}:ack` || entry.status === 'resolved'}
                  onClick={async () => {
                    setSavingKey(`${entry.id}:ack`);
                    setError('');
                    setMessage('');
                    try {
                      await alertService.ackHistory(client, entry.id);
                      setMessage(`告警事件 ${entry.id} 已确认`);
                      await reloadHistory(historyFilters);
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '确认告警失败');
                    } finally {
                      setSavingKey('');
                    }
                  }}
                >
                  确认
                </button>
                <button
                  className="h-9 rounded-md border border-amber-500/40 px-3 text-xs text-amber-300 hover:bg-amber-500/10 disabled:opacity-60"
                  disabled={savingKey === `${entry.id}:resolve` || entry.status === 'resolved'}
                  onClick={async () => {
                    setSavingKey(`${entry.id}:resolve`);
                    setError('');
                    setMessage('');
                    try {
                      await alertService.resolveHistory(client, entry.id);
                      setMessage(`告警事件 ${entry.id} 已标记恢复`);
                      await reloadHistory(historyFilters);
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '恢复告警失败');
                    } finally {
                      setSavingKey('');
                    }
                  }}
                >
                  标记恢复
                </button>
              </div>
            </li>
          ))}
          {history.length === 0 ? (
            <li className="rounded-lg border border-white/10 bg-black/10 p-3 text-xs text-slate-400">
              当前筛选条件下没有触发历史。
            </li>
          ) : null}
        </ul>
      </article>
    </section>
  );
}
