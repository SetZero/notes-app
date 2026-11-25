// Decides when to sync, and tells the interface how sync is doing.
//
// The core's `sync()` does the work; this class only chooses the moments:
// after local changes, when the server says another device changed
// something, when the browser comes back online or the tab becomes visible,
// and once a minute as a safety net.

import { CoreFailure, type Notes, type SyncReport } from "../core";
import { ChangeListener } from "../hal/ChangeListener";
import { ViewModel } from "./ViewModel";

export type SyncPhase = "idle" | "syncing" | "offline" | "error" | "revoked";

export interface SyncState {
  phase: SyncPhase;
  /** Blocks changed here that the server does not have yet. */
  pending: number;
  /** A sentence for the user when something needs their attention. */
  problem: string | null;
}

export class SyncController extends ViewModel<SyncState> {
  private static readonly AFTER_EDIT_MS = 1200;
  private static readonly SAFETY_NET_MS = 60000;
  private static readonly RETRY_OFFLINE_MS = 15000;
  private static readonly RETRY_ERROR_MS = 30000;

  private readonly listener: ChangeListener;
  private timer: number | undefined;
  private interval: number | undefined;
  private running = false;
  private again = false;
  private started = false;

  /** @param onRemoteChange called after a sync that brought in changes */
  public constructor(
    private readonly notes: Notes,
    private readonly onRemoteChange: (report: SyncReport) => void,
  ) {
    super({ phase: "idle", pending: notes.status().pending, problem: null });
    this.listener = new ChangeListener(
      () => this.notes.eventsRequest(),
      () => this.request(0),
    );
  }

  public start(): void {
    if (this.started) return;
    this.started = true;
    window.addEventListener("online", this.wake);
    window.addEventListener("offline", this.wake);
    document.addEventListener("visibilitychange", this.wakeIfVisible);
    this.interval = window.setInterval(() => this.request(0), SyncController.SAFETY_NET_MS);
    this.listener.start();
    this.request(0);
  }

  public stop(): void {
    this.started = false;
    window.removeEventListener("online", this.wake);
    window.removeEventListener("offline", this.wake);
    document.removeEventListener("visibilitychange", this.wakeIfVisible);
    window.clearInterval(this.interval);
    window.clearTimeout(this.timer);
    this.listener.stop();
  }

  /** Something was changed on this device. */
  public noteLocalChange(): void {
    this.setState({ pending: this.notes.status().pending });
    this.request(SyncController.AFTER_EDIT_MS);
  }

  /** Syncs after `delayMs`. Several requests in a row become one sync. */
  public request(delayMs: number): void {
    if (!this.started || this.state.phase === "revoked") return;
    window.clearTimeout(this.timer);
    this.timer = window.setTimeout(() => void this.run(), delayMs);
  }

  private readonly wake = (): void => this.request(0);

  private readonly wakeIfVisible = (): void => {
    if (document.visibilityState === "visible") this.request(0);
  };

  private async run(): Promise<void> {
    if (this.running) {
      this.again = true;
      return;
    }
    this.running = true;
    this.setState({ phase: "syncing" });
    try {
      const report = await this.notes.sync();
      this.setState({ phase: "idle", pending: this.notes.status().pending, problem: SyncController.describe(report) });
      if (report.pulled > 0 || report.changed_notes.length > 0) this.onRemoteChange(report);
    } catch (error) {
      this.handleFailure(CoreFailure.from(error));
    } finally {
      this.running = false;
      if (this.again) {
        this.again = false;
        this.request(0);
      }
    }
  }

  private static describe(report: SyncReport): string | null {
    if (report.clock_skew) return "This device's clock is too far ahead. Changes are kept here until it is corrected.";
    if (report.rejected > 0) return "The server refused some changes. They are kept on this device only.";
    if (report.undecryptable > 0) return "Some data from the server failed its integrity check and was ignored.";
    return null;
  }

  private handleFailure(failure: CoreFailure): void {
    const pending = this.notes.status().pending;
    switch (failure.code) {
      case "unauthorized":
        // The device was revoked from another device. Nothing more to do
        // here until the user signs in again.
        this.setState({ phase: "revoked", pending, problem: "This device was removed from the account." });
        this.listener.stop();
        return;
      case "offline":
      case "network":
        this.setState({ phase: "offline", pending, problem: null });
        this.request(SyncController.RETRY_OFFLINE_MS);
        return;
      case "rate_limited":
        this.setState({ phase: "error", pending, problem: "The server is busy. Trying again shortly." });
        this.request((failure.retryAfter ?? 30) * 1000);
        return;
      case "not_signed_in":
        this.setState({ phase: "idle", pending: 0, problem: null });
        return;
      default:
        this.setState({ phase: "error", pending, problem: `Sync failed (${failure.code}). Trying again.` });
        this.request(SyncController.RETRY_ERROR_MS);
    }
  }
}
