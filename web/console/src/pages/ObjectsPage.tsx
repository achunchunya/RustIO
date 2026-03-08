import { FormEvent, useEffect, useMemo, useState } from 'react';
import { toBilingualNotice, toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { bucketService } from '../api/services';
import type { BucketObjectEntry, BucketObjectVersionEntry, BucketSpec } from '../types';

type ObjectsPageProps = {
  client: ApiClient;
};

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function ObjectsPage({ client }: ObjectsPageProps) {
  const [buckets, setBuckets] = useState<BucketSpec[]>([]);
  const [objects, setObjects] = useState<BucketObjectEntry[]>([]);
  const [versions, setVersions] = useState<BucketObjectVersionEntry[]>([]);
  const [bucket, setBucket] = useState('');
  const [prefix, setPrefix] = useState('');
  const [selectedObjectKey, setSelectedObjectKey] = useState('');
  const [uploadKey, setUploadKey] = useState('');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [versionsError, setVersionsError] = useState('');
  const [uploading, setUploading] = useState(false);
  const [downloadingKey, setDownloadingKey] = useState('');
  const [deletingKey, setDeletingKey] = useState('');
  const [versionActionKey, setVersionActionKey] = useState('');

  const sortedObjects = useMemo(
    () => [...objects].sort((left, right) => left.key.localeCompare(right.key)),
    [objects]
  );

  async function reloadBuckets() {
    const rows = await bucketService.buckets(client);
    setBuckets(rows);
    if (!bucket && rows[0]) {
      setBucket(rows[0].name);
    }
  }

  async function reloadObjects(nextBucket = bucket, nextPrefix = prefix) {
    if (!nextBucket) {
      setObjects([]);
      return;
    }
    setLoading(true);
    try {
      const rows = await bucketService.objects(client, nextBucket, nextPrefix);
      setObjects(rows);
    } finally {
      setLoading(false);
    }
  }

  async function loadObjectVersions(objectKey: string, nextBucket = bucket) {
    if (!nextBucket) return;
    setSelectedObjectKey(objectKey);
    setVersionsError('');
    setVersionsLoading(true);
    try {
      const rows = await bucketService.objectVersions(client, nextBucket, objectKey);
      setVersions(rows);
    } catch (requestError) {
      setVersions([]);
      setVersionsError(requestError instanceof Error ? requestError.message : '加载对象版本失败');
    } finally {
      setVersionsLoading(false);
    }
  }

  async function downloadObject(objectKey: string, versionId?: string) {
    if (!bucket) return;
    const actionKey = versionId ? `${objectKey}@${versionId}` : objectKey;
    setDownloadingKey(actionKey);
    setError('');
    try {
      const blob = await bucketService.downloadObject(client, bucket, objectKey, versionId);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      const fileName = objectKey.split('/').pop() || 'object.bin';
      link.href = url;
      link.download = versionId ? `${fileName}.${versionId}` : fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : '下载对象失败');
    } finally {
      setDownloadingKey('');
    }
  }

  useEffect(() => {
    reloadBuckets()
      .then(() => reloadObjects())
      .catch((requestError) => {
        setError(requestError instanceof Error ? requestError.message : '加载对象浏览器失败');
      });
  }, [client]);

  useEffect(() => {
    setSelectedObjectKey('');
    setVersions([]);
    setVersionsError('');
  }, [bucket]);

  return (
    <section className="space-y-4">
      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h1 className="font-heading text-2xl text-white">对象浏览器</h1>
        <p className="mt-1 text-sm text-slate-300">可视化上传、下载、删除对象，并查看对象版本历史。</p>
        {error ? <p className="mt-3 text-sm text-rose-400">{toBilingualPrompt(error)}</p> : null}
        {message ? <p className="mt-3 text-sm text-signal-500">{toBilingualNotice(message)}</p> : null}

        <form
          className="mt-4 grid gap-3 rounded-xl border border-white/10 bg-black/10 p-4 md:grid-cols-3"
          onSubmit={async (event: FormEvent) => {
            event.preventDefault();
            setError('');
            setMessage('');
            try {
              await reloadObjects();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '查询对象失败');
            }
          }}
        >
          <label className="text-sm text-slate-300">
            桶
            <select
              value={bucket}
              onChange={(event) => setBucket(event.target.value)}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
            >
              {buckets.length === 0 ? <option value="">暂无桶</option> : null}
              {buckets.map((item) => (
                <option key={item.name} value={item.name}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm text-slate-300">
            前缀过滤
            <input
              value={prefix}
              onChange={(event) => setPrefix(event.target.value)}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
              placeholder="例如 logs/2026/"
            />
          </label>
          <div className="flex items-end gap-2">
            <button className="h-11 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5">
              查询对象
            </button>
            <button
              type="button"
              className="h-11 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
              onClick={async () => {
                setError('');
                try {
                  await reloadBuckets();
                  await reloadObjects();
                } catch (requestError) {
                  setError(requestError instanceof Error ? requestError.message : '刷新失败');
                }
              }}
            >
              刷新桶
            </button>
          </div>
        </form>

        <form
          className="mt-4 grid gap-3 rounded-xl border border-white/10 bg-black/10 p-4 md:grid-cols-3"
          onSubmit={async (event: FormEvent) => {
            event.preventDefault();
            if (!bucket) {
              setError('请先选择桶');
              return;
            }
            if (!uploadFile) {
              setError('请先选择文件');
              return;
            }
            const key = uploadKey.trim() || uploadFile.name;
            setUploading(true);
            setError('');
            setMessage('');
            try {
              await bucketService.uploadObject(client, bucket, key, uploadFile);
              setMessage(`对象 ${key} 上传成功`);
              setUploadKey('');
              setUploadFile(null);
              await reloadObjects(bucket, prefix);
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '上传对象失败');
            } finally {
              setUploading(false);
            }
          }}
        >
          <label className="text-sm text-slate-300">
            对象键（可选）
            <input
              value={uploadKey}
              onChange={(event) => setUploadKey(event.target.value)}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
              placeholder="默认使用文件名"
            />
          </label>
          <label className="text-sm text-slate-300">
            文件
            <input
              type="file"
              onChange={(event) => setUploadFile(event.target.files?.[0] ?? null)}
              className="mt-1 block h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 py-2 text-slate-100"
            />
          </label>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={uploading}
              className="h-11 rounded-md bg-signal-600 px-4 text-sm font-medium text-white disabled:opacity-60"
            >
              {uploading ? '上传中...' : '上传对象'}
            </button>
          </div>
        </form>
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h2 className="font-heading text-xl text-white">对象列表</h2>
        {loading ? <p className="mt-3 text-sm text-slate-300">加载中...</p> : null}
        <div className="mt-3 overflow-hidden rounded-lg border border-white/10">
          <table className="w-full text-left text-sm">
            <thead className="bg-white/5 text-slate-300">
              <tr>
                <th className="px-3 py-2">对象键</th>
                <th className="px-3 py-2">当前版本</th>
                <th className="px-3 py-2">大小</th>
                <th className="px-3 py-2">更新时间</th>
                <th className="px-3 py-2">操作</th>
              </tr>
            </thead>
            <tbody>
              {sortedObjects.map((item) => (
                <tr key={`${item.key}-${item.etag}`} className="border-t border-white/5">
                  <td className="px-3 py-2 font-mono text-xs text-signal-500">{item.key}</td>
                  <td className="px-3 py-2 text-xs text-slate-300">
                    {item.version_id ? (
                      <div className="space-y-1">
                        <p className="font-mono text-signal-500">{item.version_id}</p>
                        <p className="text-[11px] text-slate-400">
                          {item.legal_hold ? '法律保留: 开启' : '法律保留: 关闭'}
                          {item.retention_until ? ` · 保留到 ${new Date(item.retention_until).toLocaleString()}` : ''}
                        </p>
                      </div>
                    ) : (
                      <span className="text-slate-500">无</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-slate-200">{formatBytes(item.size)}</td>
                  <td className="px-3 py-2 text-slate-300">{new Date(item.last_modified).toLocaleString()}</td>
                  <td className="px-3 py-2">
                    <div className="flex gap-2">
                      <button
                        className="rounded-md border border-white/15 px-2 py-1 text-xs text-slate-100 hover:bg-white/5 disabled:opacity-60"
                        disabled={downloadingKey === item.key}
                        onClick={async () => {
                          await downloadObject(item.key);
                        }}
                      >
                        {downloadingKey === item.key ? '下载中' : '下载'}
                      </button>
                      <button
                        className="rounded-md border border-white/15 px-2 py-1 text-xs text-slate-100 hover:bg-white/5"
                        onClick={async () => {
                          await loadObjectVersions(item.key);
                        }}
                      >
                        版本
                      </button>
                      <button
                        className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                        disabled={deletingKey === item.key}
                        onClick={async () => {
                          if (!bucket) return;
                          if (!window.confirm(`确认删除对象 ${item.key}？`)) {
                            return;
                          }
                          setDeletingKey(item.key);
                          setError('');
                          setMessage('');
                          try {
                            await bucketService.deleteObject(client, bucket, item.key);
                            setMessage(`对象 ${item.key} 已删除`);
                            await reloadObjects(bucket, prefix);
                          } catch (requestError) {
                            setError(requestError instanceof Error ? requestError.message : '删除对象失败');
                          } finally {
                            setDeletingKey('');
                          }
                        }}
                      >
                        {deletingKey === item.key ? '删除中' : '删除'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {sortedObjects.length === 0 ? (
                <tr>
                  <td className="px-3 py-6 text-center text-sm text-slate-400" colSpan={5}>
                    当前无对象
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </article>

      {selectedObjectKey ? (
        <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="font-heading text-xl text-white">对象版本历史</h2>
              <p className="mt-1 font-mono text-xs text-signal-500">{selectedObjectKey}</p>
            </div>
            <button
              className="h-9 rounded-md border border-white/15 px-3 text-xs text-slate-100 hover:bg-white/5"
              onClick={async () => {
                await loadObjectVersions(selectedObjectKey);
              }}
            >
              刷新版本
            </button>
          </div>
          {versionsError ? <p className="mt-3 text-sm text-rose-400">{toBilingualPrompt(versionsError)}</p> : null}
          {versionsLoading ? <p className="mt-3 text-sm text-slate-300">版本加载中...</p> : null}
          <div className="mt-3 overflow-hidden rounded-lg border border-white/10">
            <table className="w-full text-left text-sm">
              <thead className="bg-white/5 text-slate-300">
                <tr>
                  <th className="px-3 py-2">版本 ID</th>
                  <th className="px-3 py-2">状态</th>
                  <th className="px-3 py-2">大小</th>
                  <th className="px-3 py-2">更新时间</th>
                  <th className="px-3 py-2">保留</th>
                  <th className="px-3 py-2">操作</th>
                </tr>
              </thead>
              <tbody>
                {versions.map((item) => {
                  const actionKey = `${item.key}@${item.version_id}`;
                  return (
                    <tr key={actionKey} className="border-t border-white/5">
                      <td className="px-3 py-2 font-mono text-xs text-signal-500">{item.version_id}</td>
                      <td className="px-3 py-2 text-xs text-slate-300">
                        {item.is_latest ? '最新' : '历史'} · {item.delete_marker ? '删除标记' : '对象版本'}
                      </td>
                      <td className="px-3 py-2 text-slate-200">{formatBytes(item.size)}</td>
                      <td className="px-3 py-2 text-slate-300">
                        {new Date(item.last_modified).toLocaleString()}
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-300">
                        {item.legal_hold ? '法律保留' : '无'}
                        {item.retention_until
                          ? ` · 到 ${new Date(item.retention_until).toLocaleString()}`
                          : ''}
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex gap-2">
                          <button
                            className="rounded-md border border-white/15 px-2 py-1 text-xs text-slate-100 hover:bg-white/5 disabled:opacity-60"
                            disabled={item.delete_marker || downloadingKey === actionKey}
                            onClick={async () => {
                              await downloadObject(selectedObjectKey, item.version_id);
                            }}
                          >
                            {downloadingKey === actionKey ? '下载中' : '下载版本'}
                          </button>
                          <button
                            className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                            disabled={versionActionKey === `${actionKey}:delete`}
                            onClick={async () => {
                              if (!bucket) return;
                              if (
                                !window.confirm(
                                  `确认删除版本 ${item.version_id}？该操作不可恢复。`
                                )
                              ) {
                                return;
                              }
                              setVersionActionKey(`${actionKey}:delete`);
                              setError('');
                              setMessage('');
                              try {
                                await bucketService.deleteObject(
                                  client,
                                  bucket,
                                  selectedObjectKey,
                                  item.version_id
                                );
                                setMessage(`版本 ${item.version_id} 已删除`);
                                await reloadObjects(bucket, prefix);
                                await loadObjectVersions(selectedObjectKey, bucket);
                              } catch (requestError) {
                                setError(
                                  requestError instanceof Error
                                    ? requestError.message
                                    : '删除对象版本失败'
                                );
                              } finally {
                                setVersionActionKey('');
                              }
                            }}
                          >
                            {versionActionKey === `${actionKey}:delete` ? '删除中' : '删除版本'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {!versionsLoading && versions.length === 0 ? (
                  <tr>
                    <td className="px-3 py-6 text-center text-sm text-slate-400" colSpan={6}>
                      当前对象无版本历史
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </article>
      ) : null}
    </section>
  );
}
