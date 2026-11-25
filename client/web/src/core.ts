// Typed access to the shared core (Rust, compiled to WebAssembly).
//
// Everything about accounts, encryption, the note model and sync happens
// behind this class. The rest of the web app never sees a key or a
// ciphertext.

import { WebHal } from "./hal/WebHal";
import type { EventsRequest } from "./hal/ChangeListener";
import init, { NotesApp } from "./pkg/notes_web.js";
import wasmUrl from "./pkg/notes_web_bg.wasm?url";

export interface Status {
  signed_in: boolean;
  server_url: string;
  account_id: string;
  device_id: string;
  online: boolean;
  /** Blocks changed here that the server does not have yet. */
  pending: number;
  notes: number;
}

export interface RecoveryKit {
  server_url: string;
  account_id: string;
  /** 24 words. Whoever has them can read every note. */
  phrase: string;
}

export interface NoteSummary {
  note_id: string;
  title: string;
  preview: string;
  updated_ms: number;
}

export type BlockKind = "paragraph" | "heading" | "todo" | "code";

export interface Block {
  block_id: string;
  kind: BlockKind | "attachment";
  text: string;
  attrs: Record<string, string>;
}

export interface Note {
  note_id: string;
  title: string;
  updated_ms: number;
  blocks: Block[];
}

export interface SyncReport {
  pushed: number;
  pulled: number;
  changed_notes: string[];
  rejected: number;
  clock_skew: boolean;
  undecryptable: number;
  full_resync: boolean;
}

export interface Device {
  device_id: string;
  name: string;
  created_at: string;
  last_seen_at: string;
  current: boolean;
}

/** An error from the core. `code` is stable; switch on it, not on the text. */
export class CoreFailure {
  private constructor(
    public readonly code: string,
    public readonly message: string,
    /** Seconds the server asked us to wait, if it did. */
    public readonly retryAfter: number | null,
  ) {}

  public static from(error: unknown): CoreFailure {
    const raw = error as { code?: unknown; message?: unknown; retryAfter?: unknown } | null | undefined;
    return new CoreFailure(
      typeof raw?.code === "string" ? raw.code : "unknown",
      typeof raw?.message === "string" ? raw.message : String(error),
      typeof raw?.retryAfter === "number" ? raw.retryAfter : null,
    );
  }
}

export class Notes {
  private constructor(private readonly app: NotesApp) {}

  /** Loads the WebAssembly core and the account stored in this browser. */
  public static async open(): Promise<Notes> {
    await init({ module_or_path: wasmUrl });
    const hal = await WebHal.create();
    return new Notes(await NotesApp.open(hal as never));
  }

  private static parse<T>(json: unknown): T {
    return JSON.parse(json as string) as T;
  }

  public status(): Status {
    return Notes.parse(this.app.status());
  }

  public async createAccount(serverUrl: string, inviteCode: string, deviceName: string): Promise<RecoveryKit> {
    return Notes.parse(await this.app.createAccount(serverUrl, inviteCode, deviceName));
  }

  public async recover(serverUrl: string, accountId: string, phrase: string, deviceName: string): Promise<void> {
    await this.app.recover(serverUrl, accountId, phrase, deviceName);
  }

  public recoveryKit(): RecoveryKit {
    return Notes.parse(this.app.recoveryKit());
  }

  public async signOut(revoke: boolean): Promise<void> {
    await this.app.signOut(revoke);
  }

  public async listDevices(): Promise<Device[]> {
    return Notes.parse(await this.app.listDevices());
  }

  public async revokeDevice(deviceId: string): Promise<void> {
    await this.app.revokeDevice(deviceId);
  }

  public listNotes(): NoteSummary[] {
    return Notes.parse(this.app.listNotes());
  }

  public getNote(noteId: string): Note | null {
    return Notes.parse(this.app.getNote(noteId));
  }

  public async createNote(): Promise<Note> {
    return Notes.parse(await this.app.createNote());
  }

  public async setTitle(noteId: string, title: string): Promise<void> {
    await this.app.setTitle(noteId, title);
  }

  /** Adds a block after `after`, or at the top of the note without it. */
  public async insertBlock(noteId: string, after: string | null, kind: BlockKind, text: string): Promise<Block> {
    return Notes.parse(await this.app.insertBlock(noteId, after ?? undefined, kind, text));
  }

  public async updateBlock(block: Block): Promise<void> {
    await this.app.updateBlock(block.block_id, block.kind, block.text, JSON.stringify(block.attrs));
  }

  public async deleteBlock(blockId: string): Promise<void> {
    await this.app.deleteBlock(blockId);
  }

  public async deleteNote(noteId: string): Promise<void> {
    await this.app.deleteNote(noteId);
  }

  public async sync(): Promise<SyncReport> {
    return Notes.parse(await this.app.sync());
  }

  public eventsRequest(): EventsRequest {
    return Notes.parse(this.app.eventsRequest());
  }
}
