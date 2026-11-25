import { IconCircleCheck, IconLogin2 } from "@tabler/icons-react";
import { useState, type FormEvent } from "react";
import hero from "../art/hero.webp";
import type { Provider } from "../hal/OidcSignIn";
import { AppViewModel } from "../viewmodels/AppViewModel";
import { useViewModel } from "../viewmodels/ViewModel";

type Mode = "new" | "recover";

/** "keycloak" is shown as "Keycloak". */
function label(provider: Provider): string {
  return provider.id.charAt(0).toUpperCase() + provider.id.slice(1);
}

export function Welcome({ app }: { app: AppViewModel }) {
  const state = useViewModel(app);
  // Form fields are plain view state: they matter to nobody else. After a
  // sign-in at the provider they come back as the draft, minus the secrets.
  const [mode, setMode] = useState<Mode>(state.draft?.mode ?? "new");
  const [invite, setInvite] = useState("");
  const [accountId, setAccountId] = useState(state.draft?.accountId ?? "");
  const [phrase, setPhrase] = useState("");
  const [deviceName, setDeviceName] = useState(state.draft?.deviceName ?? AppViewModel.suggestDeviceName);

  // A new account needs a sign-in, an invite code, or either of them.
  const signInOffered = state.providers.length > 0 && (mode === "recover" || state.enrollment !== "invite");
  const inviteOffered = mode === "new" && (state.enrollment !== "oidc" || state.providers.length === 0);
  const signedIn = state.signedInAs !== null;
  const ready = mode === "recover" || signedIn || inviteOffered;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (mode === "new") void app.createAccount(invite.trim(), deviceName.trim());
    else void app.recover(accountId.trim(), phrase, deviceName.trim());
  };

  if (state.join) return <Join app={app} />;

  const signIn = (provider: Provider) =>
    void app.signInWith(provider, {
      mode,
      deviceName: deviceName.trim(),
      accountId: accountId.trim(),
    });

  return (
    <main className="center scenic">
      <div className="welcome">
        <img className="mascot" src={hero} alt="" />
        <form className="card" onSubmit={submit} autoComplete="off">
          <h1 className="brand">
            Notes{" "}
            <span className="seal" aria-hidden="true">
              記
            </span>
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

          {signInOffered && (
            <div className="signin">
              {signedIn ? (
                <p className="signed-in">
                  <IconCircleCheck size={18} stroke={1.75} aria-hidden /> Signed in as <strong>{state.signedInAs}</strong>
                </p>
              ) : (
                state.providers.map((provider) => (
                  <button key={provider.id} type="button" className={inviteOffered ? "" : "primary"} disabled={state.busy} onClick={() => signIn(provider)}>
                    <IconLogin2 size={18} stroke={1.75} aria-hidden /> Sign in with {label(provider)}
                  </button>
                ))
              )}
              {mode === "recover" && !signedIn && <p className="muted hint">Only needed if the account was created with a sign-in.</p>}
              {mode === "new" && signedIn && (
                <p className="muted hint">
                  Your notes stay encrypted with a key that only your devices have. The sign-in only decides who may have an account.
                </p>
              )}
            </div>
          )}

          {inviteOffered && !signedIn && (
            <label>
              {signInOffered ? "Or an invite code" : "Invite code"}
              <input value={invite} onChange={(e) => setInvite(e.target.value)} required autoCapitalize="none" spellCheck={false} />
            </label>
          )}

          {mode === "recover" && (
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
            <button className="primary" type="submit" disabled={state.busy || !ready}>
              {state.busy ? "Working…" : mode === "new" ? "Create account" : "Open my notes"}
            </button>
          </div>
        </form>
      </div>
    </main>
  );
}

/** The screen of a device that was opened with another device's QR code. */
function Join({ app }: { app: AppViewModel }) {
  const state = useViewModel(app);
  const [deviceName, setDeviceName] = useState(AppViewModel.suggestDeviceName);
  const channel = state.join?.channel ?? null;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void app.beginJoin(deviceName.trim());
  };

  return (
    <main className="center scenic">
      <div className="welcome">
        <img className="mascot" src={hero} alt="" />
        <form className="card" onSubmit={submit} autoComplete="off">
          <h1 className="brand">
            Notes{" "}
            <span className="seal" aria-hidden="true">
              記
            </span>
          </h1>
          {channel ? (
            <>
              <p>Type this code on your other device and confirm there:</p>
              <p className="channel" aria-label={`Code ${channel.split("").join(" ")}`}>
                {channel.slice(0, 3)} {channel.slice(3)}
              </p>
              <p className="muted">Waiting for your other device… The code is good for five minutes.</p>
            </>
          ) : (
            <>
              <p className="muted">Add this device to your account. Your other device will ask you to confirm it.</p>
              <label>
                Name of this device
                <input value={deviceName} onChange={(e) => setDeviceName(e.target.value)} required maxLength={64} />
              </label>
            </>
          )}

          {state.problem && (
            <p className="problem" role="alert">
              {state.problem}
            </p>
          )}

          <div className="actions">
            <button type="button" onClick={() => app.cancelJoin()}>
              Cancel
            </button>
            {!channel && (
              <button className="primary" type="submit" disabled={state.busy}>
                {state.busy ? "Working…" : "Continue"}
              </button>
            )}
          </div>
        </form>
      </div>
    </main>
  );
}
