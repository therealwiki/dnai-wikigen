export function nextRovingTab<T extends string>(
  tabs: readonly T[],
  current: T,
  key: string,
): T | undefined {
  if (tabs.length === 0) return undefined;
  const currentIndex = tabs.indexOf(current);
  if (currentIndex < 0) return undefined;

  if (key === "ArrowRight" || key === "ArrowDown") {
    return tabs[(currentIndex + 1) % tabs.length];
  }
  if (key === "ArrowLeft" || key === "ArrowUp") {
    return tabs[(currentIndex - 1 + tabs.length) % tabs.length];
  }
  if (key === "Home") return tabs[0];
  if (key === "End") return tabs[tabs.length - 1];
  return undefined;
}
