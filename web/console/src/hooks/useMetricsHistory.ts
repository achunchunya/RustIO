import { useEffect, useRef, useState } from 'react';
import type { ApiClient } from '../api/client';
import { systemService } from '../api/services';
import type { SystemMetricsSummary } from '../types';

export type MetricsSample = {
  at: number;
  capacityRatio: number;
  usedBytes: number;
  backlogTotal: number;
  asyncPending: number;
  shardHealthy: number;
  onlinePeers: number;
};

/**
 * 实时采样:按间隔轮询 metrics summary,维护本会话内的滚动样本数组,
 * 在不引入时序后端的前提下为 sparkline/趋势图提供"活的"数据。
 */
export function useMetricsHistory(client: ApiClient, intervalMs = 5000, maxPoints = 40) {
  const [summary, setSummary] = useState<SystemMetricsSummary | null>(null);
  const [history, setHistory] = useState<MetricsSample[]>([]);
  const [error, setError] = useState('');
  const timer = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const s = await systemService.metricsSummary(client);
        if (cancelled) return;
        setSummary(s);
        setError('');
        const sample: MetricsSample = {
          at: Date.now(),
          capacityRatio: s.storage.utilization_ratio,
          usedBytes: s.storage.capacity_used_bytes,
          backlogTotal: s.replication.backlog_total,
          asyncPending: s.jobs.async_pending,
          shardHealthy: s.storage.shard_healthy_total,
          onlinePeers: s.raft.online_peers
        };
        setHistory((prev) => [...prev, sample].slice(-maxPoints));
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : '采样失败');
      }
    };
    void tick();
    timer.current = window.setInterval(tick, intervalMs);
    return () => {
      cancelled = true;
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [client, intervalMs, maxPoints]);

  return { summary, history, error };
}
