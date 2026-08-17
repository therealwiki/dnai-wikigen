import { createSignal, lazy, Match, onCleanup, onMount, Suspense, Switch } from "solid-js";
import { AppShell, type RouteKey } from "./components/AppShell";
import { wallet } from "./lib/wallet";
import type { VerificationContext } from "./lib/verificationContext";
import {
  arenaRouteForHash,
  canonicalHashForArenaRoute,
  canonicalHashForComputeTab,
  canonicalHashForRoute,
  computeTabForHash,
  routeForHash,
  titleForRoute,
  type ArenaRouteState,
} from "./routes";
import { Overview } from "./views/Overview";

const Arena = lazy(() => import("./views/Arena").then((module) => ({ default: module.Arena })));
const HealthExplorer = lazy(() => import("./views/HealthExplorer").then((module) => ({ default: module.HealthExplorer })));
const Capabilities = lazy(() => import("./views/Capabilities").then((module) => ({ default: module.Capabilities })));
const CollaboratePage = lazy(() => import("./views/CollaboratePage").then((module) => ({ default: module.CollaboratePage })));
const Compute = lazy(() => import("./views/Compute").then((module) => ({ default: module.Compute })));
const DealRoom = lazy(() => import("./views/DealRoom").then((module) => ({ default: module.DealRoom })));
const ReviewQueue = lazy(() => import("./views/ReviewQueue").then((module) => ({ default: module.ReviewQueue })));
const DataVaults = lazy(() => import("./views/DataVaults").then((module) => ({ default: module.DataVaults })));
const TinkerAccount = lazy(() => import("./views/TinkerAccount").then((module) => ({ default: module.TinkerAccount })));
const SafeguardsLab = lazy(() => import("./views/SafeguardsLab").then((module) => ({ default: module.SafeguardsLab })));
const Verify = lazy(() => import("./views/Verify").then((module) => ({ default: module.Verify })));
const NotFound = lazy(() => import("./views/NotFound").then((module) => ({ default: module.NotFound })));

export function App() {
  const [route, setRoute] = createSignal<RouteKey>(routeForHash(window.location.hash));
  const [hash, setHash] = createSignal(window.location.hash);
  const [verificationContext, setVerificationContext] = createSignal<VerificationContext>();
  const [walletDialogOpen, setWalletDialogOpen] = createSignal(false);
  wallet.useDiscovery();

  const syncRoute = () => {
    const previous = route();
    const next = routeForHash(window.location.hash);
    if (next !== "verify") setVerificationContext(undefined);
    setHash(window.location.hash);
    setRoute(next);
    document.title = titleForRoute(next);
    // A challenge tab/version change is still the same Arena page. Preserve
    // the user's scroll position and focus in that case; only a true page
    // transition should move both back to the new page's start.
    if (previous !== next) {
      window.scrollTo({ top: 0, behavior: "instant" });
      queueMicrotask(() => document.getElementById("page-content")?.focus({ preventScroll: true }));
    }
  };

  const navigateArena = (next: ArenaRouteState) => {
    const target = canonicalHashForArenaRoute(next);
    if (window.location.hash === target) {
      setHash(target);
      setRoute("arena");
      return;
    }
    window.location.hash = target;
  };

  const navigateCompute = (next: Parameters<typeof canonicalHashForComputeTab>[0]) => {
    setVerificationContext(undefined);
    const target = canonicalHashForComputeTab(next);
    if (window.location.hash === target) {
      setHash(target);
      setRoute("compute");
      return;
    }
    window.location.hash = target;
  };

  const goToRoute = (next: RouteKey) => {
    const target = canonicalHashForRoute(next);
    if (window.location.hash === target) {
      setRoute(next);
      document.title = titleForRoute(next);
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
    window.location.hash = target;
  };

  const navigate = (next: RouteKey) => {
    // Global navigation always opens a generic route. Only the explicit row
    // inspection action below may carry public projection context to Verify.
    setVerificationContext(undefined);
    goToRoute(next);
  };

  const inspectEvidence = (context: VerificationContext) => {
    setVerificationContext(context);
    goToRoute("verify");
  };

  onMount(() => {
    document.title = titleForRoute(route());
    window.addEventListener("hashchange", syncRoute);
    onCleanup(() => window.removeEventListener("hashchange", syncRoute));
  });

  return (
    <AppShell
      route={route()}
      navigate={navigate}
      walletDialogOpen={walletDialogOpen()}
      onWalletDialogOpenChange={setWalletDialogOpen}
    >
      <Suspense fallback={(
        <section class="route-loading" role="status" aria-live="polite" aria-label="Loading product surface">
          <span class="route-loading-mark" aria-hidden="true" />
          <div><strong>Opening protected surface</strong><small>Loading only the console you requested.</small></div>
        </section>
      )}>
        <Switch fallback={<Overview navigate={navigate} />}>
          <Match when={route() === "overview"}><Overview navigate={navigate} /></Match>
          <Match when={route() === "health"}><HealthExplorer navigate={navigate} /></Match>
          <Match when={route() === "arena"}>
            <Arena
              navigate={navigate}
              inspectEvidence={inspectEvidence}
              routeState={arenaRouteForHash(hash())}
              navigateArena={navigateArena}
            />
          </Match>
          <Match when={route() === "deals"}><DealRoom inspectEvidence={inspectEvidence} /></Match>
          <Match when={route() === "review"}><ReviewQueue /></Match>
          <Match when={route() === "vaults"}><DataVaults navigate={navigate} /></Match>
          <Match when={route() === "compute"}><Compute routeTab={computeTabForHash(hash())} navigateCompute={navigateCompute} inspectEvidence={inspectEvidence} /></Match>
          <Match when={route() === "tinker"}>
            <TinkerAccount
              requestWalletConnection={() => setWalletDialogOpen(true)}
              openCompute={navigateCompute}
            />
          </Match>
          <Match when={route() === "lab"}><SafeguardsLab navigate={navigate} /></Match>
          <Match when={route() === "catalog"}><Capabilities navigate={navigate} /></Match>
          <Match when={route() === "verify"}><Verify selectedEvidence={verificationContext()} clearSelectedEvidence={() => setVerificationContext(undefined)} /></Match>
          <Match when={route() === "collaborate"}>
            <CollaboratePage
              navigate={navigate}
              requestWalletConnection={() => setWalletDialogOpen(true)}
            />
          </Match>
          <Match when={route() === "not_found"}><NotFound navigate={navigate} /></Match>
        </Switch>
      </Suspense>
    </AppShell>
  );
}
