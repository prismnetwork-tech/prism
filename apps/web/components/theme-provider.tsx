"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<"light" | "dark" | null>(null);
  const pathname = usePathname();

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem("prism-theme");
      setTheme(stored === "dark" || stored === "light" ? stored : "dark");
    } catch {
      setTheme("dark");
    }
  }, []);

  useEffect(() => {
    if (!theme) return;
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem("prism-theme", theme);
    } catch {
      return;
    }
  }, [theme]);

  return (
    <>
      {pathname !== "/" ? (
        <button
          className="theme-toggle"
          type="button"
          aria-label={theme === "dark" ? "Use light theme" : "Use dark theme"}
          onClick={() => setTheme((value) => (value === "dark" ? "light" : "dark"))}
        >
          <span aria-hidden="true">{theme === "dark" ? "◑" : "◐"}</span>
        </button>
      ) : null}
      {children}
    </>
  );
}
