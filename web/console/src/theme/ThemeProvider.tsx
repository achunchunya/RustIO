import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from 'react';

/** 用户的主题偏好:auto 按时间自动,light/dark 手动锁定 */
export type ThemePreference = 'auto' | 'light' | 'dark';
/** 实际生效的主题 */
export type ResolvedTheme = 'light' | 'dark';

const STORAGE_KEY = 'rustio_theme';
/** 夜间区间 [19:00, 07:00) 走暗色 */
const NIGHT_START_HOUR = 19;
const NIGHT_END_HOUR = 7;
/** auto 模式下每 5 分钟复查一次是否跨越昼夜边界 */
const AUTO_RECHECK_MS = 5 * 60 * 1000;

const isNightHour = (hour: number) => hour >= NIGHT_START_HOUR || hour < NIGHT_END_HOUR;

const resolveTheme = (preference: ThemePreference): ResolvedTheme => {
  if (preference === 'light' || preference === 'dark') {
    return preference;
  }
  return isNightHour(new Date().getHours()) ? 'dark' : 'light';
};

const readStoredPreference = (): ThemePreference => {
  if (typeof window === 'undefined') {
    return 'auto';
  }
  const stored = window.localStorage.getItem(STORAGE_KEY);
  return stored === 'light' || stored === 'dark' || stored === 'auto' ? stored : 'auto';
};

const applyThemeClass = (theme: ResolvedTheme) => {
  if (typeof document === 'undefined') {
    return;
  }
  document.documentElement.classList.toggle('dark', theme === 'dark');
};

type ThemeContextValue = {
  preference: ThemePreference;
  theme: ResolvedTheme;
  setPreference: (preference: ThemePreference) => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(() => readStoredPreference());
  const [theme, setTheme] = useState<ResolvedTheme>(() => resolveTheme(readStoredPreference()));

  // 应用主题 class;偏好变化时立即重算
  useEffect(() => {
    const next = resolveTheme(preference);
    setTheme(next);
    applyThemeClass(next);
  }, [preference]);

  // auto 模式下:定时复查 + 回到前台/焦点时复查,跨越昼夜边界自动切换
  useEffect(() => {
    if (preference !== 'auto') {
      return;
    }
    const recheck = () => {
      const next = resolveTheme('auto');
      setTheme((current) => {
        if (current !== next) {
          applyThemeClass(next);
        }
        return next;
      });
    };
    const timer = window.setInterval(recheck, AUTO_RECHECK_MS);
    window.addEventListener('focus', recheck);
    document.addEventListener('visibilitychange', recheck);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('focus', recheck);
      document.removeEventListener('visibilitychange', recheck);
    };
  }, [preference]);

  const setPreference = useCallback((next: ThemePreference) => {
    setPreferenceState(next);
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(STORAGE_KEY, next);
    }
  }, []);

  const value = useMemo(
    () => ({ preference, theme, setPreference }),
    [preference, theme, setPreference]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error('useTheme 必须在 ThemeProvider 内使用');
  }
  return ctx;
}
