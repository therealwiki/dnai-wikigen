import { Fragment, type ReactNode } from "react";
import styles from "./JsonView.module.css";

/**
 * Dependency-free JSON syntax highlighter. Tokenizes the pretty-printed string
 * and renders classified <span>s — no dangerouslySetInnerHTML, no library.
 */
const TOKEN =
  /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?)|(\b-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?\b)|(\btrue\b|\bfalse\b)|(\bnull\b)/g;

function tokenize(json: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let last = 0;
  let key = 0;
  let match: RegExpExecArray | null;
  TOKEN.lastIndex = 0;
  while ((match = TOKEN.exec(json)) !== null) {
    if (match.index > last) {
      nodes.push(<span key={key++} className={styles.punct}>{json.slice(last, match.index)}</span>);
    }
    const [full, str, colon, num, bool, nul] = match;
    if (str !== undefined) {
      if (colon !== undefined) {
        // "key":  → split the trailing colon out so only the key is coloured
        const raw = full.replace(/\s*:$/, "");
        nodes.push(
          <Fragment key={key++}>
            <span className={styles.key}>{raw}</span>
            <span className={styles.punct}>{full.slice(raw.length)}</span>
          </Fragment>,
        );
      } else {
        nodes.push(<span key={key++} className={styles.string}>{full}</span>);
      }
    } else if (num !== undefined) {
      nodes.push(<span key={key++} className={styles.number}>{full}</span>);
    } else if (bool !== undefined) {
      nodes.push(<span key={key++} className={styles.boolean}>{full}</span>);
    } else if (nul !== undefined) {
      nodes.push(<span key={key++} className={styles.null}>{full}</span>);
    }
    last = match.index + full.length;
  }
  if (last < json.length) {
    nodes.push(<span key={key++} className={styles.punct}>{json.slice(last)}</span>);
  }
  return nodes;
}

export function JsonView({ value, label }: { value: unknown; label?: string }) {
  const json = JSON.stringify(value, null, 2);
  return (
    <pre className={`${styles.wrap} scroll-thin`} aria-label={label} tabIndex={0}>
      <code>{tokenize(json)}</code>
    </pre>
  );
}
