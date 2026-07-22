/* @refresh reload */
import { render } from "solid-js/web";
import "@fontsource-variable/manrope";
import "@fontsource-variable/jetbrains-mono";
import "./styles.css";
import { App } from "./App";
import { deployment } from "./config";

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root element");
// Give operators and browser QA a non-secret, machine-readable truth marker.
// It also makes release posture visible without treating UI text as evidence.
document.documentElement.dataset.wikigenRelease = deployment.releaseIdentityStatus
  === "release_bound" ? "release-bound" : "modeled-unconfigured";
render(() => <App />, root);
