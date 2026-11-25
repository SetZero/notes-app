// The whole app: loading, signing in, and the workspace once signed in.

import { CoreFailure, Notes, type RecoveryKit } from "../core";
import { OidcSignIn, SignInFailure, type Draft, type Enrollment, type Login, type Provider } from "../hal/OidcSignIn";
import { ViewModel } from "./ViewModel";
import { WorkspaceViewModel } from "./WorkspaceViewModel";

export type Screen = "loading" | "failed" | "welcome" | "recovery-kit" | "workspace";

export interface AppState {
  screen: Screen;
  /** While a sign-in request is running. */
  busy: boolean;
  problem: string | null;
  /** The new account's recovery kit, until the user confirms they kept it. */
  kit: RecoveryKit | null;
  workspace: WorkspaceViewModel | null;
  /** How the server lets new accounts in. */
  enrollment: Enrollment;
  /** The identity providers the server accepts a sign-in from. */
  providers: Provider[];
  /** Who is signed in at a provider, until that sign-in is used. */
  signedInAs: string | null;
  /** What the welcome screen showed before the browser left to sign in. */
  draft: Draft | null;
  /**
   * Set when this browser was opened with another device's QR code. Once
   * the pairing runs, `channel` is the number to type on that device.
   */
  join: { channel: string | null } | null;
}

export class AppViewModel extends ViewModel<AppState> {
  private notes: Notes | null = null;
  private readonly signIn = new OidcSignIn(AppViewModel.serverUrl);
  /** The sign-in to send with the next request. Its token is single use. */
  private login: Login | null = null;
  /** The secret from another device's QR code, until the pairing ends. */
  private joinSecret: string | null = null;
  private joinTimer: number | null = null;
  private static readonly JOIN_POLL_MS = 2000;

  public constructor() {
    super({
      screen: "loading",
      busy: false,
      problem: null,
      kit: null,
      workspace: null,
      enrollment: "invite",
      providers: [],
      signedInAs: null,
      draft: null,
      join: null,
    });
  }

  /** The web app always talks to the server it was loaded from. */
  private static get serverUrl(): string {
    return window.location.origin;
  }

  /** A first guess for the device name, e.g. "Firefox on Linux". */
  public static suggestDeviceName(): string {
    const agent = navigator.userAgent;
    const browser = /Edg\//.test(agent)
      ? "Edge"
      : /Firefox\//.test(agent)
        ? "Firefox"
        : /Chrome\//.test(agent)
          ? "Chrome"
          : /Safari\//.test(agent)
            ? "Safari"
            : "Browser";
    const system = /Android/.test(agent)
      ? "Android"
      : /iPhone|iPad/.test(agent)
        ? "iOS"
        : /Windows/.test(agent)
          ? "Windows"
          : /Mac OS X/.test(agent)
            ? "macOS"
            : /Linux/.test(agent)
              ? "Linux"
              : "";
    return system ? `${browser} on ${system}` : browser;
  }

  public async start(): Promise<void> {
    // Opened from another device's QR code? The secret is in the fragment,
    // which no server sees; take it out of the address bar and the history.
    const secret = new URLSearchParams(window.location.hash.slice(1)).get("join");
    if (secret) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
      this.joinSecret = secret;
    }
    try {
      this.notes = await Notes.open();
      if (this.notes.status().signed_in) this.enterWorkspace();
      else await this.showWelcome(true);
    } catch (error) {
      this.setState({
        screen: "failed",
        problem: CoreFailure.from(error).message,
      });
    }
  }

  /** Shows the welcome screen with the ways to sign in that the server offers. */
  private async showWelcome(arriving: boolean): Promise<void> {
    // Coming back from the provider's login page?
    const returned = arriving ? await this.signIn.finish() : null;
    const { enrollment, providers } = await this.signIn.options();
    this.login = returned && "login" in returned ? returned.login : null;
    this.setState({
      screen: "welcome",
      workspace: null,
      enrollment,
      providers,
      signedInAs: this.login?.name ?? null,
      draft: returned?.draft ?? null,
      problem: returned && "failure" in returned ? returned.failure : null,
      join: this.joinSecret ? { channel: null } : null,
    });
  }

  /** New device: asks the server for a pairing and waits for the other device. */
  public async beginJoin(deviceName: string): Promise<void> {
    const secret = this.joinSecret;
    if (!secret) return;
    await this.attempt(async (notes) => {
      const ticket = await notes.pairingBegin(AppViewModel.serverUrl, secret, deviceName);
      this.setState({ join: { channel: ticket.channel } });
      this.joinTimer = window.setInterval(() => void this.pollJoin(notes), AppViewModel.JOIN_POLL_MS);
    });
  }

  private async pollJoin(notes: Notes): Promise<void> {
    try {
      if (!(await notes.pairingPoll())) return;
      this.endJoin();
      this.enterWorkspace();
    } catch (error) {
      const failure = CoreFailure.from(error);
      // A dropped connection is not the end: the next round tries again.
      if (failure.code === "offline" || failure.code === "network") return;
      // The secret stays: the same QR code is good for another try.
      this.stopJoinTimer();
      this.setState({
        join: { channel: null },
        problem: AppViewModel.explain(failure),
      });
    }
  }

  /** Back to the ordinary welcome screen. */
  public cancelJoin(): void {
    this.notes?.pairingCancel();
    this.endJoin();
    this.setState({ problem: null });
  }

  private stopJoinTimer(): void {
    if (this.joinTimer !== null) window.clearInterval(this.joinTimer);
    this.joinTimer = null;
  }

  private endJoin(): void {
    this.stopJoinTimer();
    this.joinSecret = null;
    this.setState({ join: null });
  }

  /** Leaves for the provider's login page; `draft` is shown again on return. */
  public async signInWith(provider: Provider, draft: Draft): Promise<void> {
    if (this.state.busy) return;
    this.setState({ busy: true, problem: null });
    try {
      await this.signIn.begin(provider, draft);
    } catch (error) {
      const problem = error instanceof SignInFailure ? error.message : "The sign-in service cannot be reached. Check your connection.";
      this.setState({ busy: false, problem });
    }
  }

  /** With a sign-in the invite code is not needed and not sent. */
  public async createAccount(inviteCode: string, deviceName: string): Promise<void> {
    await this.attempt(async (notes) => {
      const login = this.takeLogin();
      const kit = login
        ? await notes.createAccountWithLogin(AppViewModel.serverUrl, login, deviceName)
        : await notes.createAccount(AppViewModel.serverUrl, inviteCode, deviceName);
      this.setState({ screen: "recovery-kit", kit });
    });
  }

  public async recover(accountId: string, phrase: string, deviceName: string): Promise<void> {
    await this.attempt(async (notes) => {
      await notes.recover(AppViewModel.serverUrl, accountId, phrase, deviceName, this.takeLogin());
      this.enterWorkspace();
    });
  }

  /** The sign-in, which the server accepts once: after this call it is gone. */
  private takeLogin(): Login | null {
    const login = this.login;
    this.login = null;
    if (login) this.setState({ signedInAs: null });
    return login;
  }

  /** The user says they have stored the recovery kit. */
  public confirmRecoveryKit(): void {
    this.setState({ kit: null });
    this.enterWorkspace();
  }

  private async attempt(action: (notes: Notes) => Promise<void>): Promise<void> {
    if (!this.notes || this.state.busy) return;
    this.setState({ busy: true, problem: null });
    try {
      await action(this.notes);
    } catch (error) {
      this.setState({ problem: AppViewModel.explain(CoreFailure.from(error)) });
    } finally {
      this.setState({ busy: false });
    }
  }

  private enterWorkspace(): void {
    if (!this.notes) return;
    const workspace = new WorkspaceViewModel(this.notes, () => this.leaveWorkspace());
    this.setState({ screen: "workspace", workspace, problem: null });
    workspace.start();
    // Ask the browser not to evict the local copy under storage pressure.
    void navigator.storage?.persist?.();
  }

  private leaveWorkspace(): void {
    this.state.workspace?.stop();
    void this.showWelcome(false);
  }

  private static explain(failure: CoreFailure): string {
    switch (failure.code) {
      case "invalid_invite":
        return "This invite code is not valid.";
      case "bad_phrase":
        return "The recovery phrase is not valid. Check for a mistyped or missing word; it has 24.";
      case "bad_account_id":
        return "That does not look like an account ID. It has the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.";
      case "bad_pairing_link":
        return "This link is not complete. Scan the QR code on your other device again.";
      case "pairing_expired":
        return "That took too long. Start again: the code is good for five minutes.";
      case "pairing_failed":
        return "The two devices did not agree. Open a fresh QR code on your other device and scan it again.";
      case "unauthorized":
        return "The server no longer accepts this. Start again: sign in again, or scan the QR code on your other device again.";
      case "account_exists":
        return "You already have an account. Open it with your recovery kit instead.";
      case "forbidden":
      case "not_found":
        return "The server did not accept this. Check the account ID and the recovery phrase. If a sign-in is involved, sign in again: it can be used once and for a few minutes only.";
      case "rate_limited":
        return failure.retryAfter ? `Too many attempts. Try again in ${failure.retryAfter} seconds.` : "Too many attempts. Try again in a minute.";
      case "offline":
      case "network":
        return "The server cannot be reached. Check your connection.";
      case "input":
        return failure.message;
      case "storage":
        return "The browser refused to store data. Private windows and blocked site data prevent the app from working.";
      default:
        return `That did not work (${failure.code}).`;
    }
  }
}
