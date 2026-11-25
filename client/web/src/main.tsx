import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import { AppViewModel } from "./viewmodels/AppViewModel";
import { App } from "./views/App";

// The view model lives outside React: it is created once and owns all state.
const app = new AppViewModel();
void app.start();

const root = document.getElementById("root");
if (!root) throw new Error("index.html has no #root element");
createRoot(root).render(
  <StrictMode>
    <App app={app} />
  </StrictMode>,
);
