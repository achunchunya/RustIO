import { FormEvent, useEffect, useMemo, useState } from 'react';
import { toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { bucketService } from '../api/services';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';
import { Dialog, Button, Badge, Chip, useConfirm, useToast } from '../components/ui';
import type { BucketObjectEntry, BucketObjectVersionEntry, BucketSpec } from '../types';

const IMAGE_EXT = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp', 'ico', 'avif'];
const TEXT_EXT = [
  'txt', 'json', 'log', 'md', 'markdown', 'csv', 'tsv', 'xml', 'yaml', 'yml',
  'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'css', 'scss', 'less', 'html', 'htm',
  'rs', 'go', 'py', 'java', 'kt', 'c', 'cc', 'cpp', 'h', 'hpp', 'sh', 'bash',
  'toml', 'ini', 'conf', 'cfg', 'env', 'sql', 'rb', 'php', 'pl', 'lua'
];
const TEXT_PREVIEW_MAX_BYTES = 2 * 1024 * 1024;

type PreviewKind = 'loading' | 'image' | 'pdf' | 'text' | 'toolarge' | 'unsupported' | 'error';
type PreviewState = {
  object: BucketObjectEntry;
  kind: PreviewKind;
  url?: string;
  text?: string;
  error?: string;
  ext: string;
};

type ObjectsPageProps = {
  client: ApiClient;
  canWrite?: boolean;
};

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

type FolderItem = {
  type: 'folder';
  name: string;
  fullPath: string;
};

type FileItem = {
  type: 'file';
  object: BucketObjectEntry;
};

type DisplayItem = FolderItem | FileItem;

export function ObjectsPage({ client, canWrite = true }: ObjectsPageProps) {
  const confirm = useConfirm();
  const toast = useToast();
  const [buckets, setBuckets] = useState<BucketSpec[]>([]);
  const [objects, setObjects] = useState<BucketObjectEntry[]>([]);
  const [versions, setVersions] = useState<BucketObjectVersionEntry[]>([]);
  const [bucket, setBucket] = useState('');
  const [currentPath, setCurrentPath] = useState('');
  const [selectedObjectKey, setSelectedObjectKey] = useState('');
  const [uploadKey, setUploadKey] = useState('');
  const [uploadFiles, setUploadFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [versionsError, setVersionsError] = useState('');
  const [uploading, setUploading] = useState(false);
  const [downloadingKey, setDownloadingKey] = useState('');
  const [deletingKey, setDeletingKey] = useState('');
  const [versionActionKey, setVersionActionKey] = useState('');
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set());
  const [isDragging, setIsDragging] = useState(false);
  const [preview, setPreview] = useState<PreviewState | null>(null);

  function closePreview() {
    setPreview((current) => {
      if (current?.url) URL.revokeObjectURL(current.url);
      return null;
    });
  }

  async function openPreview(object: BucketObjectEntry) {
    const ext = (object.key.split('.').pop() || '').toLowerCase();
    setPreview({ object, kind: 'loading', ext });
    try {
      const blob = await bucketService.downloadObject(client, bucket, object.key);
      if (IMAGE_EXT.includes(ext)) {
        setPreview({ object, kind: 'image', ext, url: URL.createObjectURL(blob) });
      } else if (ext === 'pdf') {
        setPreview({ object, kind: 'pdf', ext, url: URL.createObjectURL(blob) });
      } else if (TEXT_EXT.includes(ext) || (blob.type || '').startsWith('text/')) {
        if (blob.size > TEXT_PREVIEW_MAX_BYTES) {
          setPreview({ object, kind: 'toolarge', ext });
        } else {
          setPreview({ object, kind: 'text', ext, text: await blob.text() });
        }
      } else {
        setPreview({ object, kind: 'unsupported', ext });
      }
    } catch (requestError) {
      setPreview({
        object,
        kind: 'error',
        ext,
        error: requestError instanceof Error ? requestError.message : '预览失败'
      });
    }
  }

  const displayItems = useMemo<DisplayItem[]>(() => {
    const folders = new Map<string, string>();
    const files: FileItem[] = [];

    for (const obj of objects) {
      if (!obj.key.startsWith(currentPath)) continue;
      const relativePath = obj.key.slice(currentPath.length);
      const slashIndex = relativePath.indexOf('/');

      if (slashIndex > 0) {
        const folderName = relativePath.slice(0, slashIndex);
        const fullPath = currentPath + folderName + '/';
        folders.set(folderName, fullPath);
      } else if (relativePath) {
        files.push({ type: 'file', object: obj });
      }
    }

    const folderItems: FolderItem[] = Array.from(folders.entries()).map(([name, fullPath]) => ({
      type: 'folder',
      name,
      fullPath
    }));

    return [...folderItems.sort((a, b) => a.name.localeCompare(b.name)), ...files];
  }, [objects, currentPath]);

  const breadcrumbs = useMemo(() => {
    if (!currentPath) return [{ label: '根目录', path: '' }];
    const parts = currentPath.split('/').filter(Boolean);
    return [
      { label: '根目录', path: '' },
      ...parts.map((part, index) => ({
        label: part,
        path: parts.slice(0, index + 1).join('/') + '/'
      }))
    ];
  }, [currentPath]);

  async function reloadBuckets() {
    const rows = await bucketService.buckets(client);
    setBuckets(rows);
    if (!bucket && rows[0]) {
      setBucket(rows[0].name);
    }
  }

  async function reloadObjects(nextBucket = bucket) {
    if (!nextBucket) {
      setObjects([]);
      return;
    }
    setLoading(true);
    try {
      const rows = await bucketService.objects(client, nextBucket, '');
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
      toast.error(requestError instanceof Error ? requestError.message : '下载对象失败');
    } finally {
      setDownloadingKey('');
    }
  }

  async function handleUploadFiles(files: File[]) {
    if (!bucket) {
      toast.error('请先选择桶');
      return;
    }
    if (files.length === 0) return;

    setUploading(true);
    let successCount = 0;

    for (const file of files) {
      try {
        const key = currentPath + file.name;
        await bucketService.uploadObject(client, bucket, key, file);
        successCount++;
      } catch (requestError) {
        toast.error(requestError instanceof Error ? requestError.message : `上传 ${file.name} 失败`);
        break;
      }
    }

    setUploading(false);
    if (successCount > 0) {
      toast.success(`成功上传 ${successCount} 个文件`);
      setUploadFiles([]);
      await reloadObjects(bucket);
    }
  }

  async function handleDeleteSelected(reason: string) {
    if (!bucket || selectedKeys.size === 0) return;
    let successCount = 0;

    for (const key of selectedKeys) {
      try {
        await bucketService.deleteObject(client, bucket, key);
        successCount++;
      } catch (requestError) {
        toast.error(requestError instanceof Error ? requestError.message : `删除 ${key} 失败`);
        break;
      }
    }

    if (successCount > 0) {
      toast.success(`成功删除 ${successCount} 个对象`);
      setSelectedKeys(new Set());
      await reloadObjects(bucket);
    }
  }

  async function handleDeleteSingle(key: string, reason: string) {
    if (!bucket) return;
    setDeletingKey(key);
    try {
      await bucketService.deleteObject(client, bucket, key);
      toast.success(`对象 ${key} 已删除`);
      await reloadObjects(bucket);
    } catch (requestError) {
      toast.error(requestError instanceof Error ? requestError.message : '删除对象失败');
    } finally {
      setDeletingKey('');
    }
  }

  function handleDragOver(event: React.DragEvent) {
    event.preventDefault();
    setIsDragging(true);
  }

  function handleDragLeave() {
    setIsDragging(false);
  }

  function handleDrop(event: React.DragEvent) {
    event.preventDefault();
    setIsDragging(false);
    const files = Array.from(event.dataTransfer.files);
    handleUploadFiles(files);
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text).then(
      () => toast.success(`已复制: ${text}`),
      () => toast.error('复制失败')
    );
  }

  useEffect(() => {
    reloadBuckets()
      .then(() => reloadObjects())
      .catch((requestError) => {
        toast.error(requestError instanceof Error ? requestError.message : '加载对象浏览器失败');
      });
  }, [client]);

  useEffect(() => {
    setSelectedObjectKey('');
    setVersions([]);
    setVersionsError('');
    setCurrentPath('');
    setSelectedKeys(new Set());
  }, [bucket]);

  const allFilesSelected = displayItems.every(
    (item) => item.type === 'folder' || selectedKeys.has(item.object.key)
  );

  return (
    <section className="space-y-4">
      <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
        <h1 className="font-heading text-2xl text-on-surface">对象浏览器</h1>
        <p className="mt-1 text-sm text-muted">可视化上传、下载、删除对象，并查看对象版本历史。</p>

        <form
          className="mt-4 grid gap-3 rounded-xl border border-outline/60 bg-surface-container-high p-4 md:grid-cols-2"
          onSubmit={async (event: FormEvent) => {
            event.preventDefault();
            try {
              await reloadObjects();
            } catch (requestError) {
              toast.error(requestError instanceof Error ? requestError.message : '查询对象失败');
            }
          }}
        >
          <label className="text-sm text-muted">
            桶
            <select
              value={bucket}
              onChange={(event) => {
                setBucket(event.target.value);
              }}
              className="mt-1 h-11 w-full rounded-md border border-outline/60 bg-surface-lowest px-3 text-on-surface"
            >
              {buckets.length === 0 ? <option value="">暂无桶</option> : null}
              {buckets.map((item) => (
                <option key={item.name} value={item.name}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          <div className="flex items-end gap-2">
            <Button type="submit" variant="secondary">
              查询对象
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={async () => {
                try {
                  await reloadBuckets();
                  await reloadObjects();
                } catch (requestError) {
                  toast.error(requestError instanceof Error ? requestError.message : '刷新失败');
                }
              }}
            >
              刷新桶
            </Button>
          </div>
        </form>

        <div
          className={`mt-4 rounded-xl border-2 ${isDragging ? 'border-primary bg-primary/5' : 'border-dashed border-outline/60'} bg-surface-container-high p-6 transition-colors`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <p className="text-center text-sm text-muted">拖拽文件到此处上传，或使用下方按钮</p>
          <div className="mt-3 flex justify-center">
            <label className="cursor-pointer">
              <input
                type="file"
                multiple
                className="hidden"
                onChange={(event) => {
                  const files = Array.from(event.target.files || []);
                  handleUploadFiles(files);
                  event.target.value = '';
                }}
              />
              <span className="inline-block rounded-md bg-primary px-4 py-2 text-sm font-medium text-on-primary hover:opacity-90">
                {uploading ? '上传中...' : '选择文件上传'}
              </span>
            </label>
          </div>
        </div>
      </article>

      <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
        <div className="flex items-center justify-between">
          <h2 className="font-heading text-xl text-on-surface">对象列表</h2>
          {canWrite && selectedKeys.size > 0 ? (
            <ConfirmActionDialog
              title="批量删除对象"
              description={`即将删除 ${selectedKeys.size} 个对象，此操作不可撤销。`}
              actionLabel={`删除选中 (${selectedKeys.size})`}
              onConfirm={handleDeleteSelected}
            />
          ) : null}
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
          {breadcrumbs.map((crumb, index) => (
            <div key={crumb.path} className="flex items-center gap-2">
              {index > 0 ? <span className="text-muted">/</span> : null}
              <button
                className="rounded px-2 py-1 text-primary hover:bg-primary/10"
                onClick={() => setCurrentPath(crumb.path)}
              >
                {crumb.label}
              </button>
            </div>
          ))}
        </div>

        {loading ? <p className="mt-3 text-sm text-muted">加载中...</p> : null}
        <div className="mt-3 overflow-hidden rounded-lg border border-outline/60">
          <table className="w-full text-left text-sm">
            <thead className="bg-on-surface/5 text-muted">
              <tr>
                {canWrite ? (
                  <th className="px-3 py-2">
                    <input
                      type="checkbox"
                      checked={allFilesSelected && displayItems.some((item) => item.type === 'file')}
                      onChange={(event) => {
                        if (event.target.checked) {
                          const allKeys = new Set(
                            displayItems
                              .filter((item): item is FileItem => item.type === 'file')
                              .map((item) => item.object.key)
                          );
                          setSelectedKeys(allKeys);
                        } else {
                          setSelectedKeys(new Set());
                        }
                      }}
                    />
                  </th>
                ) : null}
                <th className="px-3 py-2">名称</th>
                <th className="px-3 py-2">当前版本</th>
                <th className="px-3 py-2">大小</th>
                <th className="px-3 py-2">更新时间</th>
                <th className="px-3 py-2">操作</th>
              </tr>
            </thead>
            <tbody>
              {displayItems.map((item) => {
                if (item.type === 'folder') {
                  return (
                    <tr key={item.fullPath} className="border-t border-outline/60">
                      {canWrite ? <td className="px-3 py-2"></td> : null}
                      <td className="px-3 py-2">
                        <button
                          className="flex items-center gap-2 text-primary hover:underline"
                          onClick={() => setCurrentPath(item.fullPath)}
                        >
                          📁 {item.name}
                        </button>
                      </td>
                      <td className="px-3 py-2 text-muted">—</td>
                      <td className="px-3 py-2 text-muted">—</td>
                      <td className="px-3 py-2 text-muted">—</td>
                      <td className="px-3 py-2"></td>
                    </tr>
                  );
                }

                const obj = item.object;
                const isSelected = selectedKeys.has(obj.key);

                return (
                  <tr key={`${obj.key}-${obj.etag}`} className="border-t border-outline/60">
                    {canWrite ? (
                      <td className="px-3 py-2">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={(event) => {
                            const newSelected = new Set(selectedKeys);
                            if (event.target.checked) {
                              newSelected.add(obj.key);
                            } else {
                              newSelected.delete(obj.key);
                            }
                            setSelectedKeys(newSelected);
                          }}
                        />
                      </td>
                    ) : null}
                    <td className="px-3 py-2 font-mono text-xs text-primary" title={`${bucket}/${obj.key}`}>
                      {obj.key.split('/').pop()}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted">
                      {obj.version_id ? (
                        <div className="space-y-1">
                          <p className="font-mono text-primary">{obj.version_id}</p>
                          <p className="text-[11px] text-muted">
                            {obj.legal_hold ? '法律保留: 开启' : '法律保留: 关闭'}
                            {obj.retention_until
                              ? ` · 保留到 ${new Date(obj.retention_until).toLocaleString()}`
                              : ''}
                          </p>
                        </div>
                      ) : (
                        <span className="text-muted">无</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-on-surface">{formatBytes(obj.size)}</td>
                    <td className="px-3 py-2 text-muted">{new Date(obj.last_modified).toLocaleString()}</td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-2">
                        <Button variant="tertiary" size="sm" onClick={() => openPreview(obj)}>
                          预览
                        </Button>
                        <Button
                          variant="tertiary"
                          size="sm"
                          loading={downloadingKey === obj.key}
                          onClick={() => downloadObject(obj.key)}
                        >
                          下载
                        </Button>
                        <Button variant="tertiary" size="sm" onClick={() => copyToClipboard(obj.key)}>
                          复制键
                        </Button>
                        <Button variant="tertiary" size="sm" onClick={() => loadObjectVersions(obj.key)}>
                          版本
                        </Button>
                        {canWrite ? (
                          <ConfirmActionDialog
                            title="删除对象"
                            description={`确认删除对象 ${obj.key}？此操作不可撤销。`}
                            actionLabel="删除"
                            onConfirm={(reason) => handleDeleteSingle(obj.key, reason)}
                          />
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {displayItems.length === 0 ? (
                <tr>
                  <td className="px-3 py-6 text-center text-sm text-muted" colSpan={canWrite ? 6 : 5}>
                    当前目录无内容
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </article>

      {selectedObjectKey ? (
        <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="font-heading text-xl text-on-surface">对象版本历史</h2>
              <p className="mt-1 font-mono text-xs text-primary">{selectedObjectKey}</p>
            </div>
            <Button
              variant="secondary"
              size="sm"
              loading={versionsLoading}
              onClick={async () => {
                await loadObjectVersions(selectedObjectKey);
              }}
            >
              刷新版本
            </Button>
          </div>
          {versionsError ? <p className="mt-3 text-sm text-error">{toBilingualPrompt(versionsError)}</p> : null}
          {versionsLoading ? <p className="mt-3 text-sm text-muted">加载中...</p> : null}
          <div className="mt-3 overflow-hidden rounded-lg border border-outline/60">
            <table className="w-full text-left text-sm">
              <thead className="bg-on-surface/5 text-muted">
                <tr>
                  <th className="px-3 py-2">版本 ID</th>
                  <th className="px-3 py-2">大小</th>
                  <th className="px-3 py-2">ETag</th>
                  <th className="px-3 py-2">最新</th>
                  <th className="px-3 py-2">最后修改</th>
                  <th className="px-3 py-2">操作</th>
                </tr>
              </thead>
              <tbody>
                {versions.map((item) => {
                  const actionKey = `${selectedObjectKey}:${item.version_id}`;
                  return (
                    <tr key={actionKey} className="border-t border-outline/60">
                      <td className="px-3 py-2 font-mono text-xs text-primary">{item.version_id}</td>
                      <td className="px-3 py-2 text-on-surface">{formatBytes(item.size)}</td>
                      <td className="px-3 py-2 font-mono text-xs text-muted">{item.etag}</td>
                      <td className="px-3 py-2 text-muted">{item.is_latest ? '是' : '否'}</td>
                      <td className="px-3 py-2 text-muted">
                        {new Date(item.last_modified).toLocaleString()}
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-2">
                          <Button
                            variant="tertiary"
                            size="sm"
                            loading={downloadingKey === actionKey}
                            onClick={() => downloadObject(selectedObjectKey, item.version_id)}
                          >
                            下载
                          </Button>
                          {canWrite ? (
                            <Button
                              variant="danger"
                              size="sm"
                              loading={versionActionKey === `${actionKey}:delete`}
                              onClick={async () => {
                                if (
                                  !await confirm(
                                    `确认删除版本 ${item.version_id}？此操作不可撤销。`
                                  )
                                )
                                  return;
                                setVersionActionKey(`${actionKey}:delete`);
                                try {
                                  await bucketService.deleteObject(
                                    client,
                                    bucket,
                                    selectedObjectKey,
                                    item.version_id
                                  );
                                  toast.success(`版本 ${item.version_id} 已删除`);
                                  await reloadObjects(bucket);
                                  await loadObjectVersions(selectedObjectKey, bucket);
                                } catch (requestError) {
                                  toast.error(
                                    requestError instanceof Error ? requestError.message : '删除对象版本失败'
                                  );
                                } finally {
                                  setVersionActionKey('');
                                }
                              }}
                            >
                              删除版本
                            </Button>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {!versionsLoading && versions.length === 0 ? (
                  <tr>
                    <td className="px-3 py-6 text-center text-sm text-muted" colSpan={6}>
                      当前对象无版本历史
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </article>
      ) : null}

      {preview ? (
        <Dialog
          open
          onClose={closePreview}
          title="对象预览"
          className="max-w-3xl"
          footer={
            <>
              <Button variant="tertiary" onClick={() => copyToClipboard(`${bucket}/${preview.object.key}`)}>
                复制完整路径
              </Button>
              <Button
                variant="secondary"
                onClick={() => downloadObject(preview.object.key)}
                disabled={downloadingKey === preview.object.key}
              >
                {downloadingKey === preview.object.key ? '下载中' : '下载'}
              </Button>
              <Button variant="primary" onClick={closePreview}>
                关闭
              </Button>
            </>
          }
        >
          {/* 具体路径 */}
          <div className="mb-3 rounded-md border border-outline/40 bg-surface-container-high p-3">
            <p className="text-xs uppercase tracking-wide text-muted">完整路径</p>
            <p className="mt-1 break-all font-mono text-sm text-on-surface">{bucket}/{preview.object.key}</p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <Chip>{formatBytes(preview.object.size)}</Chip>
              {preview.object.storage_class ? <Chip>{preview.object.storage_class}</Chip> : null}
              {preview.ext ? <Chip>.{preview.ext}</Chip> : null}
              {preview.object.version_id ? <Badge tone="info">版本 {preview.object.version_id.slice(0, 8)}</Badge> : null}
              <Chip>{new Date(preview.object.last_modified).toLocaleString()}</Chip>
            </div>
          </div>

          {/* 预览内容 */}
          <div className="max-h-[60vh] overflow-auto rounded-md border border-outline/40 bg-surface-lowest">
            {preview.kind === 'loading' ? (
              <p className="p-8 text-center text-sm text-muted">加载预览中...</p>
            ) : null}
            {preview.kind === 'error' ? (
              <p className="p-8 text-center text-sm text-error">{toBilingualPrompt(preview.error || '预览失败')}</p>
            ) : null}
            {preview.kind === 'image' ? (
              <div className="grid place-items-center p-4">
                <img src={preview.url} alt={preview.object.key} className="max-h-[55vh] max-w-full object-contain" />
              </div>
            ) : null}
            {preview.kind === 'pdf' ? (
              <iframe src={preview.url} title="PDF 预览" className="h-[55vh] w-full" />
            ) : null}
            {preview.kind === 'text' ? (
              <pre className="overflow-auto whitespace-pre-wrap break-all p-4 font-mono text-xs text-on-surface">
                {preview.text}
              </pre>
            ) : null}
            {preview.kind === 'toolarge' ? (
              <p className="p-8 text-center text-sm text-muted">文件较大(&gt; 2 MB),不在线预览,请下载查看。</p>
            ) : null}
            {preview.kind === 'unsupported' ? (
              <p className="p-8 text-center text-sm text-muted">该文件类型暂不支持在线预览(.{preview.ext || '未知'}),请下载查看。</p>
            ) : null}
          </div>
        </Dialog>
      ) : null}
    </section>
  );
}
