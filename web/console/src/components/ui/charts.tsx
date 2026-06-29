import { cn } from './cn';

/**
 * 自研 SVG 图表套件 —— 零第三方依赖,纯 SVG + Tailwind 语义 token(fill / stroke 颜色类),
 * 随浅/暗主题自动变色。覆盖 Sparkline / Line / Area / Bar / Donut / Gauge / DiskHeatbar。
 */

type Tone = 'primary' | 'secondary' | 'success' | 'warning' | 'error' | 'info';

const strokeTone: Record<Tone, string> = {
  primary: 'stroke-primary',
  secondary: 'stroke-secondary',
  success: 'stroke-success',
  warning: 'stroke-warning',
  error: 'stroke-error',
  info: 'stroke-info'
};
const fillTone: Record<Tone, string> = {
  primary: 'fill-primary',
  secondary: 'fill-secondary',
  success: 'fill-success',
  warning: 'fill-warning',
  error: 'fill-error',
  info: 'fill-info'
};
const textTone: Record<Tone, string> = {
  primary: 'text-primary',
  secondary: 'text-secondary',
  success: 'text-success',
  warning: 'text-warning',
  error: 'text-error',
  info: 'text-info'
};

const buildPoints = (values: number[], w: number, h: number, pad: number) => {
  if (values.length === 0) return { line: '', area: '', last: null as null | { x: number; y: number } };
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const innerW = w - pad * 2;
  const innerH = h - pad * 2;
  const stepX = values.length > 1 ? innerW / (values.length - 1) : 0;
  const pts = values.map((v, i) => {
    const x = pad + i * stepX;
    const y = pad + innerH - ((v - min) / span) * innerH;
    return { x, y };
  });
  const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const area = `${line} L${pts[pts.length - 1].x.toFixed(1)},${h - pad} L${pts[0].x.toFixed(1)},${h - pad} Z`;
  return { line, area, last: pts[pts.length - 1] };
};

/** 迷你趋势线(无轴),嵌在卡片里。 */
export function Sparkline({
  values,
  tone = 'primary',
  className,
  height = 32
}: {
  values: number[];
  tone?: Tone;
  className?: string;
  height?: number;
}) {
  const W = 100;
  const H = height;
  const { line, last } = buildPoints(values, W, H, 3);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className={cn('w-full', className)} style={{ height }}>
      {line ? <path d={line} fill="none" strokeWidth={2} className={strokeTone[tone]} vectorEffect="non-scaling-stroke" /> : null}
      {last ? <circle cx={last.x} cy={last.y} r={2.2} className={fillTone[tone]} /> : null}
    </svg>
  );
}

/** 面积趋势图(带渐隐填充 + 末点)。 */
export function AreaChart({
  values,
  tone = 'primary',
  className,
  height = 120
}: {
  values: number[];
  tone?: Tone;
  className?: string;
  height?: number;
}) {
  const W = 320;
  const H = height;
  const { line, area, last } = buildPoints(values, W, H, 8);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className={cn('w-full', className)} style={{ height }}>
      {area ? <path d={area} className={fillTone[tone]} opacity={0.12} /> : null}
      {line ? <path d={line} fill="none" strokeWidth={2} className={strokeTone[tone]} vectorEffect="non-scaling-stroke" /> : null}
      {last ? <circle cx={last.x} cy={last.y} r={3} className={fillTone[tone]} /> : null}
    </svg>
  );
}

/** 折线图(同 AreaChart 但不填充)。 */
export function LineChart(props: { values: number[]; tone?: Tone; className?: string; height?: number }) {
  const W = 320;
  const H = props.height ?? 120;
  const { line, last } = buildPoints(props.values, W, H, 8);
  const tone = props.tone ?? 'primary';
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className={cn('w-full', props.className)} style={{ height: H }}>
      {line ? <path d={line} fill="none" strokeWidth={2} className={strokeTone[tone]} vectorEffect="non-scaling-stroke" /> : null}
      {last ? <circle cx={last.x} cy={last.y} r={3} className={fillTone[tone]} /> : null}
    </svg>
  );
}

/** 横向柱状对比(带标签 + 数值)。 */
export function BarChart({
  items,
  className
}: {
  items: { label: string; value: number; tone?: Tone; display?: string }[];
  className?: string;
}) {
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <div className={cn('space-y-2', className)}>
      {items.map((item) => (
        <div key={item.label}>
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted">{item.label}</span>
            <span className="font-medium text-on-surface">{item.display ?? item.value}</span>
          </div>
          <div className="mt-1 h-2 overflow-hidden rounded-full bg-outline/30">
            <div
              className={cn('h-full rounded-full', fillTone[item.tone ?? 'primary'].replace('fill-', 'bg-'))}
              style={{ width: `${(item.value / max) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

/** 环形图:单比例(中心放标签),用于 EC 冗余度/占比。 */
export function Donut({
  ratio,
  tone = 'primary',
  size = 120,
  thickness = 12,
  label,
  sublabel,
  className
}: {
  ratio: number;
  tone?: Tone;
  size?: number;
  thickness?: number;
  label?: string;
  sublabel?: string;
  className?: string;
}) {
  const r = (size - thickness) / 2;
  const c = size / 2;
  const circumference = 2 * Math.PI * r;
  const clamped = Math.max(0, Math.min(1, ratio));
  return (
    <div className={cn('relative inline-grid place-items-center', className)} style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={c} cy={c} r={r} fill="none" strokeWidth={thickness} className="stroke-outline/40" />
        <circle
          cx={c}
          cy={c}
          r={r}
          fill="none"
          strokeWidth={thickness}
          strokeLinecap="round"
          className={strokeTone[tone]}
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - clamped)}
        />
      </svg>
      {label ? (
        <div className="absolute inset-0 grid place-items-center text-center">
          <div>
            <p className={cn('font-heading text-xl font-semibold', textTone[tone])}>{label}</p>
            {sublabel ? <p className="text-[0.65rem] text-muted">{sublabel}</p> : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

/** 半圆仪表:利用率/法定票占比。 */
export function Gauge({
  ratio,
  tone = 'primary',
  size = 140,
  label,
  sublabel,
  className
}: {
  ratio: number;
  tone?: Tone;
  size?: number;
  label?: string;
  sublabel?: string;
  className?: string;
}) {
  const thickness = 12;
  const r = (size - thickness) / 2;
  const c = size / 2;
  const clamped = Math.max(0, Math.min(1, ratio));
  // 半圆:从左(180°)到右(0°)
  const startAngle = Math.PI;
  const endAngle = Math.PI * (1 - clamped);
  const point = (angle: number) => `${(c + r * Math.cos(angle)).toFixed(1)},${(c - r * Math.sin(angle)).toFixed(1)}`;
  const track = `M ${point(Math.PI)} A ${r} ${r} 0 0 1 ${point(0)}`;
  const value = `M ${point(startAngle)} A ${r} ${r} 0 0 1 ${point(endAngle)}`;
  return (
    <div className={cn('inline-flex flex-col items-center', className)}>
      <svg width={size} height={size / 2 + thickness} viewBox={`0 0 ${size} ${size / 2 + thickness}`}>
        <path d={track} fill="none" strokeWidth={thickness} strokeLinecap="round" className="stroke-outline/40" />
        {clamped > 0 ? (
          <path d={value} fill="none" strokeWidth={thickness} strokeLinecap="round" className={strokeTone[tone]} />
        ) : null}
      </svg>
      {label ? <p className={cn('-mt-2 font-heading text-2xl font-semibold', textTone[tone])}>{label}</p> : null}
      {sublabel ? <p className="text-xs text-muted">{sublabel}</p> : null}
    </div>
  );
}

/** 逐盘健康热力条带:每个磁盘一个色块,快速定位异常盘。 */
export function DiskHeatbar({
  disks,
  className
}: {
  disks: { id: string; tone: Tone }[];
  className?: string;
}) {
  return (
    <div className={cn('flex flex-wrap gap-1', className)}>
      {disks.map((d) => (
        <span
          key={d.id}
          title={d.id}
          className={cn('h-5 w-5 rounded-sm', fillTone[d.tone].replace('fill-', 'bg-'))}
        />
      ))}
    </div>
  );
}
