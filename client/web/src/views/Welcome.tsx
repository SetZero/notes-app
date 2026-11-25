import { useState, type FormEvent } from "react";
import hero from "../art/hero.webp";
import { AppViewModel } from "../viewmodels/AppViewModel";
import { useViewModel } from "../viewmodels/ViewModel";

type Mode = "new" | "recover";

export function Welcome({ app }: { app: AppViewModel }) {
  const state = useViewModel(app);
  // Form fields are plain view state: they matter to nobody else.
  const [mode, setMode] = useState<Mode>("new");
  const [invite, setInvite] = useState("");
  const [accountId, setAccountId] = useState("");
  const [phrase, setPhrase] = useState("");
  const [deviceName, setDeviceName] = useState(AppViewModel.suggestDeviceName);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (mode === "new") void app.createAccount(invite.trim(), deviceName.trim());
    else void app.recover(accountId.trim(), phrase, deviceName.trim());
  };

  return (
    <main className="center scenic">
      <div className="welcome">
        <img className="mascot" src={hero} alt="" />
      <form className="card" onSubmit={submit} autoComplete="off">
        <h1 className="brand">
          Notes <span aria-hidden="true">✿</span>
        </h1>
        <p className="muted">Okaeri! Your notes are end-to-end encrypted and readable on your devices only.</p>

        <div className="tabs" role="tablist">
          <button type="button" role="tab" aria-selected={mode === "new"} onClick={() => setMode("new")}>
            New account
          </button>
          <button type="button" role="tab" aria-selected={mode === "recover"} onClick={() => setMode("recover")}>
            I have a recovery kit
          </button>
        </div>

        {mode === "new" ? (
          <label>
            Invite code
            <input value={invite} onChange={(e) => setInvite(e.target.value)} required autoCapitalize="none" spellCheck={false} />
          </label>
        ) : (
          <>
            <label>
              Account ID
              <input
                className="mono"
                value={accountId}
                onChange={(e) => setAccountId(e.target.value)}
                required
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                autoCapitalize="none"
                spellCheck={false}
              />
            </label>
            <label>
              Recovery phrase (24 words)
              <textarea
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                required
                rows={4}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                translate="no"
              />
            </label>
          </>
        )}

        <label>
          Name of this device
          <input value={deviceName} onChange={(e) => setDeviceName(e.target.value)} required maxLength={64} />
        </label>

        {state.problem && (
          <p className="problem" role="alert">
            {state.problem}
          </p>
        )}

        <div className="actions">
          <button className="primary" type="submit" disabled={state.busy}>
            {state.busy ? "Working…" : mode === "new" ? "Create account" : "Open my notes"}
          </button>
        </div>
      </form>
      </div>
    </main>
  );
}
