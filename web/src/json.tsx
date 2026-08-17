// Minimal, dependency-free JSON syntax highlighter.
// Input is always our own synthetic data (no user-supplied HTML), but we still
// escape strings defensively before injecting markup.

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function highlightJson(value: unknown): string {
  const json = JSON.stringify(value, null, 2);
  // Tokenize strings (incl. keys), numbers, booleans, null.
  return esc(json).replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match) => {
      let cls = "n"; // number
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? "k" : "s"; // key vs string
      } else if (/true|false/.test(match)) {
        cls = "b";
      } else if (/null/.test(match)) {
        cls = "nul";
      }
      return `<span class="${cls}">${match}</span>`;
    },
  );
}

export function JsonBlock(props: { value: unknown; label?: string }) {
  return (
    <pre
      class="json"
      tabindex="0"
      role="region"
      aria-label={props.label ?? "JSON data"}
      innerHTML={highlightJson(props.value)}
    />
  );
}
