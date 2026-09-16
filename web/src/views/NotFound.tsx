import { ArrowRight, Compass, Home, ShieldCheck } from "lucide-solid";
import type { RouteKey } from "../components/AppShell";

export function NotFound(props: { navigate: (route: RouteKey) => void }) {
  return (
    <div class="page-wrap product-page not-found-page">
      <section class="not-found-card" aria-labelledby="not-found-title">
        <span class="not-found-mark"><Compass size={28} /></span>
        <p class="overline">Canonical route boundary · no fallback content</p>
        <h1 id="not-found-title">That product surface does not exist.</h1>
        <p>The address was not recognized, so Wikigen did not silently substitute the Overview or infer a nearby workflow. No wallet action, upload, or service request was started.</p>
        <div class="not-found-actions">
          <button class="primary-button large" type="button" onClick={() => props.navigate("overview")}><Home size={17} /> Return to Overview</button>
          <button class="secondary-button large" type="button" onClick={() => props.navigate("verify")}><ShieldCheck size={17} /> Open trust center <ArrowRight size={15} /></button>
        </div>
      </section>
    </div>
  );
}
