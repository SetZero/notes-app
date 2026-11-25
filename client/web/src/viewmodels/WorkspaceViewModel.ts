// The signed-in app: the list of notes, which one is open, and the dialogs.

import { CoreFailure, type Device, type NoteSummary, type Notes, type RecoveryKit, type SyncReport } from "../core";
import { EditorViewModel } from "./EditorViewModel";
import { SyncController } from "./SyncController";
import { ViewModel } from "./ViewModel";

export type Dialog = "devices" | "add-device" | "recovery" | "sign-out" | null;

/** Adding a device: show the QR code, look up the new device's number, confirm, done. */
export interface AddDevice {
  /** What the QR code holds: this app's address with the pairing secret in the fragment. */
  link: string;
  step: "show" | "confirm" | "done";
  /** The name the new device gave itself, once its number was looked up. */
  deviceName: string | null;
  busy: boolean;
}

export interface WorkspaceState {
  notes: NoteSummary[];
  query: string;
  /** The folder whose notes are listed; `null` lists all notes. */
  folder: string | null;
  selectedId: string | null;
  /** The editor of the selected note. Replaced when another note is opened. */
  editor: EditorViewModel | null;
  dialog: Dialog;
  devices: Device[] | null;
  addDevice: AddDevice | null;
  /** Shown in the recovery dialog only after the user asks for it. */
  kit: RecoveryKit | null;
  problem: string | null;
}

export class WorkspaceViewModel extends ViewModel<WorkspaceState> {
  public readonly sync: SyncController;
  /** The secret in the QR code that is on screen. */
  private pairingSecret: string | null = null;

  /** @param onSignedOut called after the account was removed from this browser */
  public constructor(
    private readonly notes: Notes,
    private readonly onSignedOut: () => void,
  ) {
    super({
      notes: notes.listNotes(),
      query: "",
      folder: null,
      selectedId: null,
      editor: null,
      dialog: null,
      devices: null,
      addDevice: null,
      kit: null,
      problem: null,
    });
    this.sync = new SyncController(notes, (report) => this.applyRemoteChanges(report));
  }

  public start(): void {
    this.sync.start();
  }

  public stop(): void {
    this.sync.stop();
  }

  public get accountId(): string {
    return this.notes.status().account_id;
  }

  // ---------------------------------------------------------------- notes

  /** The notes in the chosen folder (and its subfolders) matching the search box. */
  public get visibleNotes(): NoteSummary[] {
    const query = this.state.query.trim().toLowerCase();
    const folder = this.state.folder;
    return this.state.notes.filter(
      (n) =>
        (folder === null || n.folder === folder || n.folder.startsWith(`${folder}/`)) &&
        (!query || n.title.toLowerCase().includes(query) || n.preview.toLowerCase().includes(query)),
    );
  }

  /**
   * Every folder that has a note in it or below it, sorted so that a folder
   * comes right before its subfolders. Folders are not stored on their own.
   */
  public get folders(): string[] {
    const all = new Set<string>();
    for (const note of this.state.notes) {
      const parts = note.folder ? note.folder.split("/") : [];
      for (let depth = 1; depth <= parts.length; depth += 1) all.add(parts.slice(0, depth).join("/"));
    }
    return [...all].sort((a, b) => a.localeCompare(b));
  }

  public showFolder(folder: string | null): void {
    this.setState({ folder });
  }

  public setQuery(query: string): void {
    this.setState({ query });
  }

  public async select(noteId: string | null): Promise<void> {
    if (noteId === this.state.selectedId) return;
    const previous = this.state.editor;
    this.setState({
      selectedId: noteId,
      editor: noteId ? new EditorViewModel(this.notes, noteId, () => this.afterLocalChange()) : null,
    });
    await previous?.dispose();
  }

  public async createNote(): Promise<void> {
    try {
      const note = await this.notes.createNote(this.state.folder ?? "");
      this.setState({ query: "" });
      this.afterLocalChange();
      await this.select(note.note_id);
      this.state.editor?.focusTitle();
    } catch (error) {
      this.setState({
        problem: `The note could not be created (${CoreFailure.from(error).code}).`,
      });
    }
  }

  public async deleteSelected(): Promise<void> {
    const noteId = this.state.selectedId;
    if (!noteId) return;
    try {
      await this.select(null);
      await this.notes.deleteNote(noteId);
      this.afterLocalChange();
    } catch (error) {
      this.setState({
        problem: `The note could not be deleted (${CoreFailure.from(error).code}).`,
      });
    }
  }

  private afterLocalChange(): void {
    this.refreshNotes();
    this.sync.noteLocalChange();
  }

  private refreshNotes(): void {
    const notes = this.notes.listNotes();
    // A folder disappears with its last note; do not keep showing it empty.
    const folder = this.state.folder;
    const exists = folder === null || notes.some((n) => n.folder === folder || n.folder.startsWith(`${folder}/`));
    this.setState({ notes, folder: exists ? folder : null });
  }

  private applyRemoteChanges(report: SyncReport): void {
    this.refreshNotes();
    const selected = this.state.selectedId;
    if (selected && (report.changed_notes.includes(selected) || report.full_resync)) this.state.editor?.reload();
  }

  // -------------------------------------------------------------- dialogs

  public open(dialog: Dialog): void {
    this.endPairing();
    this.setState({ dialog, kit: null, devices: null, problem: null });
    if (dialog === "devices") void this.loadDevices();
    if (dialog === "add-device") this.showPairingCode();
  }

  public close(): void {
    // Do not keep the recovery phrase or a pairing secret in memory longer than shown.
    this.endPairing();
    this.setState({ dialog: null, kit: null, devices: null });
  }

  // ---------------------------------------------------------- add a device

  /** A new secret and its QR code. Every opening of the dialog has its own. */
  private showPairingCode(): void {
    try {
      this.pairingSecret = this.notes.newPairingSecret();
      const link = `${window.location.origin}${window.location.pathname}#join=${this.pairingSecret}`;
      this.setState({
        addDevice: { link, step: "show", deviceName: null, busy: false },
      });
    } catch (error) {
      this.setState({
        problem: WorkspaceViewModel.explain(CoreFailure.from(error)),
      });
    }
  }

  private endPairing(): void {
    if (this.pairingSecret) this.notes.pairingCancel();
    this.pairingSecret = null;
    if (this.state.addDevice) this.setState({ addDevice: null });
  }

  /** Looks up the device that shows `code`, to ask the user about it. */
  public async findNewDevice(code: string): Promise<void> {
    await this.pairingStep(async (current) => {
      const found = await this.notes.pairingClaim(code);
      this.setState({
        addDevice: {
          ...current,
          step: "confirm",
          deviceName: found.device_name,
          busy: false,
        },
      });
    });
  }

  /** The user said yes: the new device gets the account key. */
  public async approveNewDevice(): Promise<void> {
    const secret = this.pairingSecret;
    if (!secret) return;
    await this.pairingStep(async (current) => {
      await this.notes.pairingApprove(secret);
      this.pairingSecret = null;
      this.setState({ addDevice: { ...current, step: "done", busy: false } });
    });
  }

  private async pairingStep(action: (current: AddDevice) => Promise<void>): Promise<void> {
    const current = this.state.addDevice;
    if (!current || current.busy) return;
    this.setState({ addDevice: { ...current, busy: true }, problem: null });
    try {
      await action(current);
    } catch (error) {
      // Still open? Then the user may try again with the same QR code.
      if (this.state.addDevice)
        this.setState({
          addDevice: {
            ...current,
            step: "show",
            deviceName: null,
            busy: false,
          },
        });
      this.setState({
        problem: WorkspaceViewModel.explain(CoreFailure.from(error)),
      });
    }
  }

  public revealRecoveryKit(): void {
    this.setState({ kit: this.notes.recoveryKit() });
  }

  private async loadDevices(): Promise<void> {
    try {
      this.setState({ devices: await this.notes.listDevices() });
    } catch (error) {
      this.setState({
        problem: WorkspaceViewModel.explain(CoreFailure.from(error)),
      });
    }
  }

  public async revokeDevice(deviceId: string): Promise<void> {
    try {
      await this.notes.revokeDevice(deviceId);
      await this.loadDevices();
    } catch (error) {
      this.setState({
        problem: WorkspaceViewModel.explain(CoreFailure.from(error)),
      });
    }
  }

  /** Removes the account from this browser and tells the server to forget this device. */
  public async signOut(): Promise<void> {
    await this.state.editor?.dispose();
    this.sync.stop();
    await this.notes.signOut(true);
    this.onSignedOut();
  }

  public dismissProblem(): void {
    this.setState({ problem: null });
  }

  private static explain(failure: CoreFailure): string {
    switch (failure.code) {
      case "bad_pairing_code":
        return "The code has six digits.";
      case "not_found":
        return "No device shows this code right now. Check the six digits on the new device.";
      case "pairing_state_conflict":
        return "This code was already used. Scan the QR code again on the new device to get a new one.";
      case "pairing_expired":
        return "That took too long. Scan the QR code again on the new device.";
      case "pairing_failed":
        return "The new device sent something invalid. Scan the QR code again on the new device.";
      case "rate_limited":
        return failure.retryAfter ? `Too many attempts. Try again in ${failure.retryAfter} seconds.` : "Too many attempts. Try again in a minute.";
      case "offline":
      case "network":
        return "The server cannot be reached right now.";
      case "unauthorized":
        return "This device was removed from the account.";
      case "rate_limited":
        return "Too many requests. Please wait a moment.";
      default:
        return `That did not work (${failure.code}).`;
    }
  }
}
