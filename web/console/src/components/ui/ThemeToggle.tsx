import { useTheme, type ThemePreference } from '../../theme/ThemeProvider';
import { cn } from './cn';
import { IconSun, IconMoon, IconAuto } from './icons';

const options: { value: ThemePreference; label: string; Icon: typeof IconSun }[] = [
  { value: 'light', label: '浅色', Icon: IconSun },
  { value: 'dark', label: '暗色', Icon: IconMoon },
  { value: 'auto', label: '自动', Icon: IconAuto }
];

/** 主题三态切换:浅色 / 暗色 / 自动(按时间)。 */
export function ThemeToggle({ className }: { className?: string }) {
  const { preference, setPreference } = useTheme();
  return (
    <div
      className={cn('inline-flex rounded-md border border-outline/50 p-0.5', className)}
      role="group"
      aria-label="主题切换"
    >
      {options.map(({ value, label, Icon }) => {
        const isActive = preference === value;
        return (
          <button
            key={value}
            onClick={() => setPreference(value)}
            title={label}
            aria-label={label}
            aria-pressed={isActive}
            className={cn(
              'rounded p-1.5 transition',
              isActive
                ? 'bg-primary text-on-primary'
                : 'text-muted hover:text-on-surface'
            )}
          >
            <Icon size={16} />
          </button>
        );
      })}
    </div>
  );
}
