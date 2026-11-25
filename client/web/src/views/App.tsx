import type { AppViewModel } from "../viewmodels/AppViewModel";
import { useViewModel } from "../viewmodels/ViewModel";
import icon from "../art/icon.webp";
import { RecoveryKitCard } from "./RecoveryKitCard";
import { Welcome } from "./Welcome";
import { Workspace } from "./Workspace";

export function App({ app }: { app: AppViewModel }) {
  const state = useViewModel(app);

  switch (state.screen) {
    case "loading":
      return (
        <main className="center scenic">
          <div className="loading">
            <img src={icon} alt="" width={96} height={96} />
            <p className="muted">Opening your notes…</p>
          </div>
        </main>
      );
    case "failed":
      return (
        <main className="center scenic">
          <div className="card">
            <h1>Notes could not start</h1>
            <p>{state.problem}</p>
            <p className="muted">The app needs WebAssembly and permission to store data in this browser.</p>
          </div>
        </main>
      );
    case "welcome":
      return <Welcome app={app} />;
    case "recovery-kit":
      return (
        <main className="center scenic">
          <div className="card wide">
            <h1>Your recovery kit ✿</h1>
            <p>
              Write these down and keep them somewhere safe. They are the only way to open your notes on a new device, and nobody can
              restore them for you: the server never sees them.
            </p>
            {state.kit && <RecoveryKitCard kit={state.kit} />}
            <div className="actions">
              <button className="primary" onClick={() => app.confirmRecoveryKit()}>
                I have stored it
              </button>
            </div>
          </div>
        </main>
      );
    case "workspace":
      return state.workspace ? <Workspace workspace={state.workspace} /> : null;
  }
}
