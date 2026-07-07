import styles from "./Header.module.css";

type Props = {
  nav: { id: string; label: string }[];
  activeId: string;
};

export function Header({ nav, activeId }: Props) {
  return (
    <header className={styles.header}>
      <div className={styles.inner}>
        <a className={styles.brand} href="#main" aria-label="The Gate: Health — wikigen.me, home">
          <span className={styles.mark} aria-hidden="true">
            wg
          </span>
          The&nbsp;Gate<span className={styles.brandSub}>· wikigen.me</span>
        </a>
        <nav className={styles.nav} aria-label="Sections">
          {nav.map((item) => (
            <a
              key={item.id}
              className={styles.link}
              href={`#${item.id}`}
              aria-current={activeId === item.id ? "true" : undefined}
            >
              {item.label}
            </a>
          ))}
        </nav>
      </div>
    </header>
  );
}
