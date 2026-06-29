import { cn } from './cn';

type LogoProps = {
  /** 整体高度(px),宽度自适应 */
  size?: number;
  /** 是否显示 RustIO 文字 */
  withWordmark?: boolean;
  className?: string;
};

/**
 * RustIO 品牌标识 —— 按设计稿重画的矢量 R 字标 + 圆点。
 * R 用 currentColor(随父级文字色/主题变化),圆点用品牌 secondary(檀木紫)。
 */
export function LogoMark({ size = 28, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      className={className}
      role="img"
      aria-label="RustIO"
    >
      {/* R 主体:竖笔 + 弧形头 + 斜撇,line 风格 */}
      <path
        d="M14 38V12.5C14 11.1 15.1 10 16.5 10H27c5 0 8.5 3.2 8.5 7.7 0 4-2.7 6.8-6.8 7.5L36 38"
        stroke="currentColor"
        strokeWidth="3.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M14 25h12.5"
        stroke="currentColor"
        strokeWidth="3.4"
        strokeLinecap="round"
      />
      {/* 品牌圆点 */}
      <circle cx="37.5" cy="34" r="3.2" className="fill-secondary" />
    </svg>
  );
}

export function Logo({ size = 28, withWordmark = true, className }: LogoProps) {
  return (
    <span className={cn('inline-flex items-center gap-2.5', className)}>
      <LogoMark size={size} />
      {withWordmark ? (
        <span
          className="font-heading font-semibold tracking-tight"
          style={{ fontSize: size * 0.72 }}
        >
          Rust<span className="text-secondary">IO</span>
        </span>
      ) : null}
    </span>
  );
}
