const ZH_EN_SEPARATOR = ' / ';
const CHINESE_RE = /[\u4e00-\u9fff]/;

const EXACT_ZH_TO_EN: Record<string, string> = {
  登录失败: 'Login failed',
  刷新失败: 'Refresh failed',
  失败: 'Failed',
  警告: 'Warning',
  请先选择桶: 'Please select a bucket first',
  请先选择文件: 'Please select a file first',
  '成员用户名不能为空': 'Member username cannot be empty',
  'principal 不能为空': 'Principal cannot be empty',
  '至少选择一个通知渠道': 'Select at least one notification channel',
  '规则至少需要一个通知渠道': 'Each rule must include at least one notification channel',
  '静默窗口至少选择一个规则': 'Select at least one rule for a silence window',
  '请填写有效的开始和结束时间': 'Please provide valid start and end times',
  '升级策略至少选择一个通知渠道': 'Select at least one channel for escalation policy',
  '升级策略至少需要一个通知渠道': 'Escalation policy must include at least one channel',
  '通知规则的 ID、事件、目标不能为空': 'Notification rule ID, event, and target cannot be empty',
  '生命周期规则 ID 不能为空': 'Lifecycle rule ID cannot be empty',
  '生命周期规则 ID 不能重复': 'Lifecycle rule IDs cannot be duplicated',
  '标签 Key 不能为空': 'Tag key cannot be empty',
  'CORS 规则 ID 不能为空': 'CORS rule ID cannot be empty',
  '配置必须是 JSON 对象': 'Configuration must be a JSON object',
  '租户硬配额必须大于 0': 'Tenant hard quota must be greater than 0',
  审计文件已导出: 'Audit file exported',
  安全配置已更新: 'Security settings updated',
  'KMS 密钥轮换任务已提交': 'KMS key rotation job submitted',
  修复任务已启动: 'Heal job started'
};

type PatternRule = {
  regex: RegExp;
  toEn: (...args: string[]) => string;
};

const PATTERN_RULES: PatternRule[] = [
  {
    regex: /^通知规则 ID (.+) 已存在$/,
    toEn: (id) => `Notification rule ID ${id} already exists`
  },
  {
    regex: /^生命周期规则 ID (.+) 已存在$/,
    toEn: (id) => `Lifecycle rule ID ${id} already exists`
  },
  {
    regex: /^标签 Key (.+) 已存在$/,
    toEn: (key) => `Tag key ${key} already exists`
  },
  {
    regex: /^CORS 规则 ID (.+) 已存在$/,
    toEn: (id) => `CORS rule ID ${id} already exists`
  },
  {
    regex: /^CORS 规则 (.+) 缺少 AllowedOrigin$/,
    toEn: (id) => `CORS rule ${id} is missing AllowedOrigin`
  },
  {
    regex: /^CORS 规则 (.+) 缺少 AllowedMethod$/,
    toEn: (id) => `CORS rule ${id} is missing AllowedMethod`
  },
  {
    regex: /^CORS 规则 (.+) 的 MaxAgeSeconds 必须是大于等于 0 的数字$/,
    toEn: (id) => `CORS rule ${id} MaxAgeSeconds must be a number >= 0`
  },
  {
    regex: /^生命周期规则 (.+) 的状态必须是 Enabled 或 Disabled$/,
    toEn: (id) => `Lifecycle rule ${id} status must be Enabled or Disabled`
  },
  {
    regex: /^生命周期规则 (.+) 的 (.+) 必须为正整数$/,
    toEn: (id, field) => `Lifecycle rule ${id} ${field} must be a positive integer`
  },
  {
    regex: /^生命周期规则 (.+) 至少需要一个过期条件$/,
    toEn: (id) => `Lifecycle rule ${id} requires at least one expiration condition`
  },
  {
    regex: /^加载(.+)失败$/,
    toEn: (target) => `Failed to load ${target}`
  },
  {
    regex: /^保存(.+)失败$/,
    toEn: (target) => `Failed to save ${target}`
  },
  {
    regex: /^刷新(.+)失败$/,
    toEn: (target) => `Failed to refresh ${target}`
  },
  {
    regex: /^导出(.+)失败$/,
    toEn: (target) => `Failed to export ${target}`
  },
  {
    regex: /^应用(.+)失败$/,
    toEn: (target) => `Failed to apply ${target}`
  },
  {
    regex: /^校验(.+)失败$/,
    toEn: (target) => `Failed to validate ${target}`
  },
  {
    regex: /^创建(.+)失败$/,
    toEn: (target) => `Failed to create ${target}`
  },
  {
    regex: /^新增(.+)失败$/,
    toEn: (target) => `Failed to create ${target}`
  },
  {
    regex: /^生成(.+)失败$/,
    toEn: (target) => `Failed to generate ${target}`
  },
  {
    regex: /^启动(.+)失败$/,
    toEn: (target) => `Failed to start ${target}`
  },
  {
    regex: /^执行(.+)失败$/,
    toEn: (target) => `Failed to execute ${target}`
  },
  {
    regex: /^模拟(.+)失败$/,
    toEn: (target) => `Failed to simulate ${target}`
  },
  {
    regex: /^测试(.+)失败$/,
    toEn: (target) => `Failed to test ${target}`
  },
  {
    regex: /^更新(.+)失败$/,
    toEn: (target) => `Failed to update ${target}`
  },
  {
    regex: /^启用(.+)失败$/,
    toEn: (target) => `Failed to enable ${target}`
  },
  {
    regex: /^禁用(.+)失败$/,
    toEn: (target) => `Failed to disable ${target}`
  },
  {
    regex: /^暂停(.+)失败$/,
    toEn: (target) => `Failed to suspend ${target}`
  },
  {
    regex: /^上线(.+)失败$/,
    toEn: (target) => `Failed to bring ${target} online`
  },
  {
    regex: /^下线(.+)失败$/,
    toEn: (target) => `Failed to take ${target} offline`
  },
  {
    regex: /^删除(.+)失败$/,
    toEn: (target) => `Failed to delete ${target}`
  },
  {
    regex: /^取消(.+)失败$/,
    toEn: (target) => `Failed to cancel ${target}`
  },
  {
    regex: /^清除(.+)失败$/,
    toEn: (target) => `Failed to clear ${target}`
  },
  {
    regex: /^清空(.+)失败$/,
    toEn: (target) => `Failed to clear ${target}`
  },
  {
    regex: /^上传(.+)失败$/,
    toEn: (target) => `Failed to upload ${target}`
  },
  {
    regex: /^下载(.+)失败$/,
    toEn: (target) => `Failed to download ${target}`
  },
  {
    regex: /^检索(.+)失败$/,
    toEn: (target) => `Failed to query ${target}`
  },
  {
    regex: /^查询(.+)失败$/,
    toEn: (target) => `Failed to query ${target}`
  },
  {
    regex: /^重置(.+)失败$/,
    toEn: (target) => `Failed to reset ${target}`
  },
  {
    regex: /^回滚(.+)失败$/,
    toEn: (target) => `Failed to rollback ${target}`
  },
  {
    regex: /^轮换(.+)失败$/,
    toEn: (target) => `Failed to rotate ${target}`
  },
  {
    regex: /^重试(.+)失败$/,
    toEn: (target) => `Failed to retry ${target}`
  },
  {
    regex: /^挂载(.+)失败$/,
    toEn: (target) => `Failed to attach ${target}`
  },
  {
    regex: /^解绑(.+)失败$/,
    toEn: (target) => `Failed to detach ${target}`
  },
  {
    regex: /^添加(.+)失败$/,
    toEn: (target) => `Failed to add ${target}`
  },
  {
    regex: /^移除(.+)失败$/,
    toEn: (target) => `Failed to remove ${target}`
  },
  {
    regex: /^回收(.+)失败$/,
    toEn: (target) => `Failed to revoke ${target}`
  },
  {
    regex: /^认领(.+)失败$/,
    toEn: (target) => `Failed to claim ${target}`
  },
  {
    regex: /^确认(.+)失败$/,
    toEn: (target) => `Failed to acknowledge ${target}`
  },
  {
    regex: /^恢复(.+)失败$/,
    toEn: (target) => `Failed to resolve ${target}`
  },
  {
    regex: /^(.+)不能为空$/,
    toEn: (field) => `${field} cannot be empty`
  },
  {
    regex: /^(.+)创建成功$/,
    toEn: (target) => `${target} created successfully`
  },
  {
    regex: /^(.+)上传成功$/,
    toEn: (target) => `${target} uploaded successfully`
  },
  {
    regex: /^(.+)已更新$/,
    toEn: (target) => `${target} updated`
  },
  {
    regex: /^(.+)已删除$/,
    toEn: (target) => `${target} deleted`
  },
  {
    regex: /^(.+)已清除$/,
    toEn: (target) => `${target} cleared`
  },
  {
    regex: /^(.+)已取消$/,
    toEn: (target) => `${target} cancelled`
  },
  {
    regex: /^(.+)已暂停$/,
    toEn: (target) => `${target} suspended`
  },
  {
    regex: /^(.+)已恢复$/,
    toEn: (target) => `${target} resumed`
  },
  {
    regex: /^(.+)已上线$/,
    toEn: (target) => `${target} is online`
  },
  {
    regex: /^(.+)已下线$/,
    toEn: (target) => `${target} is offline`
  },
  {
    regex: /^已为 (.+) 创建 STS 会话$/,
    toEn: (principal) => `Created STS session for ${principal}`
  },
  {
    regex: /^诊断报告已生成：(.+)$/,
    toEn: (id) => `Diagnostic report generated: ${id}`
  },
  {
    regex: /^配置版本 (.+) 已应用$/,
    toEn: (version) => `Configuration version ${version} applied`
  },
  {
    regex: /^配置已回滚到 (.+)$/,
    toEn: (version) => `Configuration rolled back to ${version}`
  },
  {
    regex: /^已同步当前配置到编辑器$/,
    toEn: () => 'Synced current config to editor'
  },
  {
    regex: /^站点 (.+) 已切换为主站$/,
    toEn: (site) => `Site ${site} promoted as primary`
  },
  {
    regex: /^站点 (.+) 已完成 Failback$/,
    toEn: (site) => `Site ${site} failback completed`
  }
];

function translateToEnglish(message: string, fallbackEnglish: string): string {
  const exact = EXACT_ZH_TO_EN[message];
  if (exact) {
    return exact;
  }

  for (const rule of PATTERN_RULES) {
    const match = message.match(rule.regex);
    if (match) {
      return rule.toEn(...match.slice(1));
    }
  }

  return fallbackEnglish;
}

function toBilingualMessage(message: string, fallbackChinese: string, fallbackEnglish: string): string {
  const normalized = message.trim();
  if (!normalized) {
    return `${fallbackChinese}${ZH_EN_SEPARATOR}${fallbackEnglish}`;
  }

  if (normalized.includes(ZH_EN_SEPARATOR)) {
    return normalized;
  }

  if (CHINESE_RE.test(normalized)) {
    return `${normalized}${ZH_EN_SEPARATOR}${translateToEnglish(normalized, fallbackEnglish)}`;
  }

  return `${fallbackChinese}${ZH_EN_SEPARATOR}${normalized}`;
}

function toChineseOnlyMessage(message: string, fallbackChinese: string): string {
  const normalized = message.trim();
  if (!normalized) {
    return fallbackChinese;
  }

  if (normalized.includes(ZH_EN_SEPARATOR)) {
    return normalized.split(ZH_EN_SEPARATOR)[0]?.trim() || fallbackChinese;
  }

  if (CHINESE_RE.test(normalized)) {
    return normalized;
  }

  return fallbackChinese;
}

export function toBilingualPrompt(message: string): string {
  return toChineseOnlyMessage(message, '请求失败');
}

export function toBilingualNotice(message: string): string {
  return toChineseOnlyMessage(message, '操作提示');
}
