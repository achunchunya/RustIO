/**
 * 产品优势基准常量 —— 来源于仓库基准脚本与 README(非实时,标注为"基准")。
 * scripts/list-bench、scripts/throughput-bench、EC criterion 基准、作战地图。
 */

export const LIST_BENCH = {
  // scripts/list-bench/run.sh,20000 对象,同进程唯一变量 RUSTIO_LIST_WALK_FS
  singlePageRedbMs: 6.7,
  singlePageWalkMs: 167.4,
  singlePageSpeedup: 25,
  fullPageRedbMs: 149,
  fullPageWalkMs: 3462,
  fullPageSpeedup: 23,
  objects: 20000
};

export const THROUGHPUT_BENCH = {
  // scripts/throughput-bench(release,ARM M 系列)
  singleNodeGetGiBs: 4.6,
  singleNodePutGiBs: 0.86,
  clusterGetGiBs: 1.7,
  minioClusterGetGiBs: 2.1 // 公开同类数字,作对照
};

export const EC_BENCH = {
  // reed-solomon-erasure galois_8 simd-accel(NEON),16MB (8,2)
  encodeSimdGiBs: 17.6,
  encodeBaselineGiBs: 3.1,
  encodeSpeedup: 5.7,
  reconstructSimdGiBs: 12.5,
  reconstructBaselineGiBs: 3.07,
  reconstructSpeedup: 4
};

/** 安全加固清单(已落地,见作战地图安全维度) */
export const SECURITY_HARDENING = [
  'Basic auth 恒定时间比较(constant_time_eq,消除长度泄漏)',
  '安全响应头中间件(X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy)',
  '登录失败 10 次触发账户级 lockout(跨 IP,管理员可解锁)',
  '注入防护与输入校验'
];

/** 差异化定位(对标 MinIO/RustFS) */
export const DIFFERENTIATORS = [
  {
    key: 'list',
    title: 'LIST 元数据索引',
    headline: '25× 更快',
    desc: 'redb 有序 KV 索引,单页延迟与桶规模解耦(O(log n+page));MinIO 每次 LIST 都 walk 文件系统(O(n),海量对象崩溃)。'
  },
  {
    key: 'scale',
    title: '在线弹性扩缩',
    headline: '零停机',
    desc: '运行时在线增删节点 + 存量数据再平衡;MinIO erasure set 创建后不可变、扩容需停机加整组。'
  },
  {
    key: 'raft',
    title: 'Raft 强一致控制面',
    headline: 'HA + 故障转移',
    desc: 'openraft 多节点 HA + 优雅 Leader 转移 + 动态成员;MinIO 控制面无共识。'
  },
  {
    key: 'consistency',
    title: '分层混合一致性',
    headline: '三层各取最优',
    desc: '数据=quorum 多副本 / 元数据=redb 有序索引 / 控制面=raft 强一致;业界没有一家这么分层。'
  },
  {
    key: 'throughput',
    title: 'EC NEON SIMD + 高吞吐',
    headline: '5.7× 编码',
    desc: 'reed-solomon NEON/AVX SIMD 全平台默认;单机 GET 吞吐已超 MinIO 集群 2×。'
  },
  {
    key: 'admin',
    title: '全开源完整 Admin',
    headline: '无锁定',
    desc: 'IAM / OIDC / LDAP / KMS / 治理 / 控制台全开源;正是 MinIO 2025 砍掉并锁进商业版的部分。'
  }
];
