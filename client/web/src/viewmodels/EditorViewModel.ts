// One open note: its title and blocks, and every way to edit them.
//
// Typing changes the state at once and is written to the core a moment
// later; structural edits (new block, delete, merge) are written right away.
// All writes go through one queue, so they reach the core in the order the
// user made them.

import { CoreFailure, type Block, type BlockKind, type Notes } from "../core";
import { ViewModel } from "./ViewModel";

/** Where the caret should go after the next render. */
export interface FocusRequest {
  target: string | "title";
  position: number | "end";
  /** Changes with every request, so the same target can be asked for twice. */
  sequence: number;
}

/** How an attachment is shown. Anything not known to be safe inline is a download. */
export type MediaKind = "image" | "audio" | "video" | "file";

/** The decrypted file of an attachment block, ready for the page to use. */
export interface Media {
  kind: MediaKind;
  /** A blob: URL that lives as long as the note is open. */
  url: string | null;
  problem: string | null;
}

export interface EditorState {
  noteId: string;
  title: string;
  /** Folder path like "Work/Plans"; empty for none. */
  folder: string;
  /** Decrypted attachments by block id, filled as the view asks for them. */
  media: Record<string, Media>;
  /** Files being encrypted and added right now. */
  attaching: number;
  blocks: Block[];
  focus: FocusRequest | null;
  problem: string | null;
  /** The note was deleted, here or on another device. */
  gone: boolean;
}

export class EditorViewModel extends ViewModel<EditorState> {
  private static readonly SAVE_DELAY_MS = 350;
  private static readonly TITLE = "title";
  private static readonly MAX_ATTACHMENT_BYTES = 24 * 1024 * 1024;

  /**
   * Types the browser may render itself. Everything else, SVG and HTML in
   * particular, is only ever offered as a download with a neutral type, so a
   * file can never run as part of this page.
   */
  private static readonly INLINE: Record<string, MediaKind> = {
    "image/png": "image",
    "image/jpeg": "image",
    "image/gif": "image",
    "image/webp": "image",
    "image/avif": "image",
    "image/bmp": "image",
    "audio/mpeg": "audio",
    "audio/mp4": "audio",
    "audio/x-m4a": "audio",
    "audio/aac": "audio",
    "audio/ogg": "audio",
    "audio/wav": "audio",
    "audio/x-wav": "audio",
    "audio/webm": "audio",
    "audio/flac": "audio",
    "video/mp4": "video",
    "video/webm": "video",
    "video/ogg": "video",
    "video/quicktime": "video",
  };

  /** Pending saves, by block id (or "title"). */
  private readonly timers = new Map<string, number>();
  private queue: Promise<void> = Promise.resolve();
  private focusSequence = 0;
  private disposed = false;

  /** @param onLocalChange called after every write to the core */
  public constructor(
    private readonly notes: Notes,
    noteId: string,
    private readonly onLocalChange: () => void,
  ) {
    const note = notes.getNote(noteId);
    super({
      noteId,
      title: note?.title ?? "",
      folder: note?.folder ?? "",
      media: {},
      attaching: 0,
      blocks: note?.blocks ?? [],
      focus: null,
      problem: null,
      gone: note === null,
    });
  }

  // ------------------------------------------------------------- typing

  public setTitle(title: string): void {
    this.setState({ title: title.replace(/\n/g, " ") });
    this.schedule(EditorViewModel.TITLE);
  }

  /** @param caret where the caret is in `text` */
  public editBlock(blockId: string, text: string, caret: number): void {
    const block = this.find(blockId);
    if (!block) return;
    const shortcut = block.kind === "paragraph" ? EditorViewModel.shortcut(text) : null;
    if (shortcut) {
      this.replace({ ...block, kind: shortcut.kind, text: shortcut.text });
      // The prefix is gone, so the caret moves left by its length.
      this.focus(blockId, Math.max(0, caret - (text.length - shortcut.text.length)));
    } else {
      this.replace({ ...block, text });
    }
    this.schedule(blockId);
  }

  /** Moves the note into a folder ("Work/Plans"), or out of all with "". */
  public setFolder(folder: string): void {
    const cleaned = folder
      .split("/")
      .map((part) => part.trim())
      .filter((part) => part !== "")
      .join("/");
    if (cleaned === this.state.folder) return;
    this.setState({ folder: cleaned });
    this.enqueue(() => this.notes.setFolder(this.state.noteId, cleaned));
  }

  /** Markdown-style prefixes typed at the start of a paragraph. */
  private static shortcut(text: string): { kind: BlockKind; text: string } | null {
    const rules: [RegExp, BlockKind][] = [
      [/^#{1,3} /, "heading"],
      [/^(- )?\[ ?\] /, "todo"],
      [/^```/, "code"],
    ];
    for (const [pattern, kind] of rules) {
      const match = pattern.exec(text);
      if (match) return { kind, text: text.slice(match[0].length) };
    }
    return null;
  }

  // ---------------------------------------------------------- structure

  public setKind(blockId: string, kind: BlockKind): void {
    const block = this.find(blockId);
    if (!block || block.kind === kind) return;
    this.replace({ ...block, kind, attrs: {} });
    this.saveNow(blockId);
    this.focus(blockId, "end");
  }

  public toggleDone(blockId: string): void {
    const block = this.find(blockId);
    if (!block || block.kind !== "todo") return;
    const done = block.attrs.done === "true";
    this.replace({ ...block, attrs: done ? {} : { done: "true" } });
    this.saveNow(blockId);
  }

  /** Enter: the text after the caret moves into a new block below. */
  public splitBlock(blockId: string, caret: number): void {
    const block = this.find(blockId);
    if (!block) return;
    // Enter in an empty heading or to-do item ends the list instead.
    if (block.text === "" && block.kind !== "paragraph") {
      this.setKind(blockId, "paragraph");
      return;
    }
    const before = block.text.slice(0, caret);
    const after = block.text.slice(caret);
    const kind: BlockKind = block.kind === "todo" ? "todo" : "paragraph";
    this.cancel(blockId);
    const shortened = { ...block, text: before };
    this.replace(shortened);
    this.enqueue(async () => {
      await this.notes.updateBlock(shortened);
      const created = await this.notes.insertBlock(this.state.noteId, blockId, kind, after);
      const blocks = [...this.state.blocks];
      const index = blocks.findIndex((b) => b.block_id === blockId);
      blocks.splice(index < 0 ? blocks.length : index + 1, 0, created);
      this.setState({ blocks });
      this.focus(created.block_id, 0);
    });
  }

  /** Backspace at the very start of a block. */
  public backspaceAtStart(blockId: string): void {
    const index = this.state.blocks.findIndex((b) => b.block_id === blockId);
    const block = this.state.blocks[index];
    if (!block) return;
    if (block.kind !== "paragraph") {
      this.setKind(blockId, "paragraph");
      this.focus(blockId, 0);
      return;
    }
    const previous = this.state.blocks[index - 1];
    if (!previous) {
      if (block.text === "") this.focus(EditorViewModel.TITLE, "end");
      return;
    }
    // Join with the block above.
    const joined = { ...previous, text: previous.text + block.text };
    this.cancel(blockId);
    this.cancel(previous.block_id);
    this.setState({
      blocks: this.state.blocks.filter((b) => b.block_id !== blockId).map((b) => (b.block_id === joined.block_id ? joined : b)),
    });
    this.focus(previous.block_id, previous.text.length);
    this.enqueue(async () => {
      await this.notes.updateBlock(joined);
      await this.notes.deleteBlock(blockId);
    });
  }

  public removeBlock(blockId: string): void {
    const index = this.state.blocks.findIndex((b) => b.block_id === blockId);
    if (index < 0) return;
    this.cancel(blockId);
    const blocks = this.state.blocks.filter((b) => b.block_id !== blockId);
    this.setState({ blocks });
    const neighbour = blocks[index] ?? blocks[index - 1];
    this.focus(neighbour ? neighbour.block_id : EditorViewModel.TITLE, "end");
    this.enqueue(() => this.notes.deleteBlock(blockId));
  }

  /** A new empty paragraph at the end, for clicking below the last block. */
  public appendBlock(): void {
    const last = this.state.blocks.at(-1);
    if (last && last.kind === "paragraph" && last.text === "") {
      this.focus(last.block_id, 0);
      return;
    }
    this.enqueue(async () => {
      const created = await this.notes.insertBlock(this.state.noteId, last?.block_id ?? null, "paragraph", "");
      this.setState({ blocks: [...this.state.blocks, created] });
      this.focus(created.block_id, 0);
    });
  }

  // -------------------------------------------------------- attachments

  /**
   * Adds files (pasted, dropped or picked) below the block `after`, or at
   * the end of the note without it. Each file is encrypted on this device
   * before anything is stored or sent.
   */
  public attachFiles(files: File[], after: string | null): void {
    let previous = after ?? this.state.blocks.at(-1)?.block_id ?? null;
    for (const file of files) {
      if (file.size > EditorViewModel.MAX_ATTACHMENT_BYTES) {
        this.setState({
          problem: `"${file.name}" is larger than 24 MB and cannot be attached.`,
        });
        continue;
      }
      this.setState({ attaching: this.state.attaching + 1 });
      this.enqueue(async () => {
        try {
          const data = new Uint8Array(await file.arrayBuffer());
          const created = await this.notes.addAttachment(this.state.noteId, previous, file.name, file.type, data);
          const blocks = [...this.state.blocks];
          const index = blocks.findIndex((b) => b.block_id === previous);
          blocks.splice(index < 0 ? blocks.length : index + 1, 0, created);
          previous = created.block_id;
          this.setState({ blocks });
        } finally {
          this.setState({ attaching: this.state.attaching - 1 });
        }
      });
    }
  }

  /**
   * Changes how an attachment is shown: `width` (percent of the note's
   * width), `align` (left, center, right) and `caption` ("hidden").
   * An empty value removes the attribute.
   */
  public setDisplay(blockId: string, change: Record<string, string>): void {
    const block = this.find(blockId);
    if (!block || block.kind !== "attachment") return;
    const attrs = { ...block.attrs };
    for (const [name, value] of Object.entries(change)) {
      if (value === "") delete attrs[name];
      else attrs[name] = value;
    }
    this.replace({ ...block, attrs });
    this.saveNow(blockId);
  }

  /** Moves a block to just before or just after another one. */
  public moveBlock(blockId: string, targetId: string, place: "before" | "after"): void {
    if (blockId === targetId) return;
    const moving = this.find(blockId);
    if (!moving) return;
    const blocks = this.state.blocks.filter((b) => b.block_id !== blockId);
    const target = blocks.findIndex((b) => b.block_id === targetId);
    if (target < 0) return;
    const index = place === "before" ? target : target + 1;
    blocks.splice(index, 0, moving);
    if (blocks.every((b, i) => b === this.state.blocks[i])) return;
    const after = blocks[index - 1]?.block_id ?? null;
    // Pending text of the moved block must reach the core before the move.
    if (this.timers.has(blockId)) this.saveNow(blockId);
    this.setState({ blocks });
    this.enqueue(() => this.notes.moveBlock(blockId, after));
  }

  /** Decrypts an attachment for display. The view calls this when it shows one. */
  public loadMedia(blockId: string): void {
    const block = this.find(blockId);
    if (!block || block.kind !== "attachment" || this.state.media[blockId]) return;
    const kind = EditorViewModel.INLINE[block.attrs.mime ?? ""] ?? "file";
    this.setMedia(blockId, { kind, url: null, problem: null });
    void this.notes.attachment(blockId).then(
      (bytes) => {
        if (this.disposed) return;
        const type = kind === "file" ? "application/octet-stream" : block.attrs.mime;
        const url = URL.createObjectURL(new Blob([bytes], { type }));
        this.setMedia(blockId, { kind, url, problem: null });
      },
      (error: unknown) => {
        if (!this.disposed)
          this.setMedia(blockId, {
            kind,
            url: null,
            problem: EditorViewModel.explainMedia(CoreFailure.from(error)),
          });
      },
    );
  }

  private setMedia(blockId: string, media: Media): void {
    this.setState({ media: { ...this.state.media, [blockId]: media } });
  }

  private static explainMedia(failure: CoreFailure): string {
    switch (failure.code) {
      case "not_uploaded":
        return "Not uploaded yet by the device it was added on.";
      case "offline":
      case "network":
        return "Not on this device yet. It will load when you are online.";
      case "corrupt":
        return "This file failed its integrity check and was not opened.";
      default:
        return `The file could not be loaded (${failure.code}).`;
    }
  }

  // -------------------------------------------------------------- caret

  /** For a note that was just created: start typing its title. */
  public focusTitle(): void {
    this.focus(EditorViewModel.TITLE, "end");
  }

  /** Arrow up or down out of a block (or out of the title). */
  public moveFocus(from: string | "title", direction: -1 | 1): void {
    const blocks = this.state.blocks;
    const index = from === EditorViewModel.TITLE ? -1 : blocks.findIndex((b) => b.block_id === from);
    const next = blocks[index + direction];
    if (next) this.focus(next.block_id, direction === 1 ? 0 : "end");
    else if (direction === -1 && index === 0) this.focus(EditorViewModel.TITLE, "end");
  }

  private focus(target: string, position: number | "end"): void {
    this.focusSequence += 1;
    this.setState({
      focus: { target, position, sequence: this.focusSequence },
    });
  }

  // ------------------------------------------------------------ storage

  /** Called after a sync changed this note: show what the other device did. */
  public reload(): void {
    // After the queue, so that our own writes are in the core already.
    this.enqueue(async () => {
      const note = this.notes.getNote(this.state.noteId);
      if (!note) {
        this.setState({ gone: true });
        return;
      }
      // What the user typed and we have not saved yet stays as typed.
      const local = new Map(this.state.blocks.map((b) => [b.block_id, b]));
      const blocks = note.blocks.map((b) => (this.timers.has(b.block_id) ? (local.get(b.block_id) ?? b) : b));
      // Attachments that could not be loaded get another try.
      const media = Object.fromEntries(Object.entries(this.state.media).filter(([, m]) => m.problem === null));
      this.setState({
        blocks,
        media,
        folder: note.folder,
        title: this.timers.has(EditorViewModel.TITLE) ? this.state.title : note.title,
        gone: false,
      });
    }, false);
  }

  /** Writes everything still waiting. Resolves when the core has it all. */
  public flush(): Promise<void> {
    for (const key of [...this.timers.keys()]) this.saveNow(key);
    return this.queue;
  }

  /** Call when the note is closed. */
  public async dispose(): Promise<void> {
    await this.flush();
    this.disposed = true;
    for (const media of Object.values(this.state.media)) {
      if (media.url) URL.revokeObjectURL(media.url);
    }
  }

  public dismissProblem(): void {
    this.setState({ problem: null });
  }

  private find(blockId: string): Block | undefined {
    return this.state.blocks.find((b) => b.block_id === blockId);
  }

  private replace(block: Block): void {
    this.setState({
      blocks: this.state.blocks.map((b) => (b.block_id === block.block_id ? block : b)),
    });
  }

  private schedule(key: string): void {
    this.cancel(key);
    this.timers.set(
      key,
      window.setTimeout(() => this.saveNow(key), EditorViewModel.SAVE_DELAY_MS),
    );
  }

  private cancel(key: string): void {
    window.clearTimeout(this.timers.get(key));
    this.timers.delete(key);
  }

  private saveNow(key: string): void {
    this.cancel(key);
    if (key === EditorViewModel.TITLE) {
      const title = this.state.title;
      this.enqueue(() => this.notes.setTitle(this.state.noteId, title));
      return;
    }
    const block = this.find(key);
    if (block) this.enqueue(() => this.notes.updateBlock(block));
  }

  private enqueue(job: () => Promise<void>, isLocalChange = true): void {
    this.queue = this.queue
      .then(job)
      .then(() => {
        if (isLocalChange) this.onLocalChange();
      })
      .catch((error: unknown) => {
        if (!this.disposed)
          this.setState({
            problem: EditorViewModel.explain(CoreFailure.from(error)),
          });
      });
  }

  private static explain(failure: CoreFailure): string {
    switch (failure.code) {
      case "too_long":
        return "This block is too long to save. Split it into several blocks.";
      case "too_large":
        return "This file is too large to attach.";
      case "not_found":
        return "This part of the note was deleted on another device.";
      case "storage":
        return "The browser could not save your change. Is its storage full or blocked?";
      default:
        return `The change could not be saved (${failure.code}).`;
    }
  }
}
