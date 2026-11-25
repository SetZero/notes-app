// The signed-in app: the list of notes, which one is open, and the dialogs.

import { CoreFailure, type Device, type NoteSummary, type Notes, type RecoveryKit, type SyncReport } from "../core";
import { EditorViewModel } from "./EditorViewModel";
import { SyncController } from "./SyncController";
import { ViewModel } from "./ViewModel";

export type Dialog = "devices" | "recovery" | "sign-out" | null;

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
  /** Shown in the recovery dialog only after the user asks for it. */
  kit: RecoveryKit | null;
  problem: string | null;
}

export class WorkspaceViewModel extends ViewModel<WorkspaceState> {
  public readonly sync: SyncController;

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
      this.setState({ problem: `The note could not be created (${CoreFailure.from(error).code}).` });
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
      this.setState({ problem: `The note could not be deleted (${CoreFailure.from(error).code}).` });
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
    this.setState({ dialog, kit: null, devices: null, problem: null });
    if (dialog === "devices") void this.loadDevices();
  }

  public close(): void {
    // Do not keep the recovery phrase in memory longer than it is shown.
    this.setState({ dialog: null, kit: null, devices: null });
  }

  public revealRecoveryKit(): void {
    this.setState({ kit: this.notes.recoveryKit() });
  }

  private async loadDevices(): Promise<void> {
    try {
      this.setState({ devices: await this.notes.listDevices() });
    } catch (error) {
      this.setState({ problem: WorkspaceViewModel.explain(CoreFailure.from(error)) });
    }
  }

  public async revokeDevice(deviceId: string): Promise<void> {
    try {
      await this.notes.revokeDevice(deviceId);
      await this.loadDevices();
    } catch (error) {
      this.setState({ problem: WorkspaceViewModel.explain(CoreFailure.from(error)) });
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
