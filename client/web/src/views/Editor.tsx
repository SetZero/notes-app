import { useEffect, useRef, useState, type ClipboardEvent, type DragEvent, type KeyboardEvent } from "react";
import type { Block, BlockKind } from "../core";
import type { EditorViewModel } from "../viewmodels/EditorViewModel";
import { useViewModel } from "../viewmodels/ViewModel";
import { Attachment } from "./Attachment";
import { AutoTextarea } from "./AutoTextarea";

const KINDS: [BlockKind, string][] = [
  ["paragraph", "Text"],
  ["heading", "Heading"],
  ["todo", "To-do"],
  ["code", "Code"],
];

/** True when the caret has no line above (direction -1) or below (1) it. */
function atEdge(area: HTMLTextAreaElement, direction: -1 | 1): boolean {
  if (area.selectionStart !== area.selectionEnd) return false;
  return direction === -1 ? !area.value.slice(0, area.selectionStart).includes("\n") : !area.value.slice(area.selectionEnd).includes("\n");
}

/** The block a paste or drop happened in, so files land right below it. */
function blockAt(target: EventTarget): string | null {
  return target instanceof Element ? (target.closest<HTMLElement>("[data-block-id]")?.dataset.blockId ?? null) : null;
}

export function Editor({ editor }: { editor: EditorViewModel }) {
  const state = useViewModel(editor);
  const container = useRef<HTMLDivElement>(null);
  const [dragging, setDragging] = useState(false);

  // Put the caret where the view model asked for it.
  const focus = state.focus;
  useEffect(() => {
    if (!focus) return;
    const area = container.current?.querySelector<HTMLTextAreaElement>(`[data-focus-id="${CSS.escape(focus.target)}"]`);
    if (!area) return;
    const position = focus.position === "end" ? area.value.length : focus.position;
    area.focus();
    area.setSelectionRange(position, position);
    // Only when a new request arrives, not on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus?.sequence]);

  if (state.gone) {
    return (
      <div className="editor">
        <p className="muted">This note was deleted.</p>
      </div>
    );
  }

  const paste = (event: ClipboardEvent<HTMLDivElement>) => {
    const files = [...event.clipboardData.files];
    if (files.length === 0) return; // Plain text: the textarea handles it.
    event.preventDefault();
    editor.attachFiles(files, blockAt(event.target));
  };

  const hasFiles = (event: DragEvent) => event.dataTransfer.types.includes("Files");

  const dragOver = (event: DragEvent<HTMLDivElement>) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
    setDragging(true);
  };

  const drop = (event: DragEvent<HTMLDivElement>) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    setDragging(false);
    editor.attachFiles([...event.dataTransfer.files], blockAt(event.target));
  };

  const titleKey = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" || (event.key === "ArrowDown" && atEdge(event.currentTarget, 1))) {
      event.preventDefault();
      if (state.blocks.length === 0) editor.appendBlock();
      else editor.moveFocus("title", 1);
    }
  };

  const blockKey = (block: Block, event: KeyboardEvent<HTMLTextAreaElement>) => {
    const area = event.currentTarget;
    if (event.nativeEvent.isComposing) return;
    const modifier = event.ctrlKey || event.metaKey;
    // In code, Enter is a line break; Ctrl+Enter leaves the block.
    if (event.key === "Enter" && !event.shiftKey && (block.kind !== "code" || modifier)) {
      event.preventDefault();
      editor.splitBlock(block.block_id, block.kind === "code" ? area.value.length : area.selectionStart);
    } else if (event.key === "Backspace" && area.selectionStart === 0 && area.selectionEnd === 0) {
      event.preventDefault();
      editor.backspaceAtStart(block.block_id);
    } else if (event.key === "ArrowUp" && !event.shiftKey && atEdge(area, -1)) {
      event.preventDefault();
      editor.moveFocus(block.block_id, -1);
    } else if (event.key === "ArrowDown" && !event.shiftKey && atEdge(area, 1)) {
      const last = state.blocks.at(-1)?.block_id === block.block_id;
      if (last) return;
      event.preventDefault();
      editor.moveFocus(block.block_id, 1);
    }
  };

  return (
    <div
      className={`editor${dragging ? " dragging" : ""}`}
      ref={container}
      onPaste={paste}
      onDragOver={dragOver}
      onDragLeave={() => setDragging(false)}
      onDrop={drop}
    >
      {state.problem && (
        <p className="problem" role="alert">
          {state.problem}{" "}
          <button className="link" onClick={() => editor.dismissProblem()}>
            Dismiss
          </button>
        </p>
      )}

      <AutoTextarea
        className="title"
        data-focus-id="title"
        value={state.title}
        placeholder="Title"
        aria-label="Title"
        onChange={(e) => editor.setTitle(e.target.value)}
        onKeyDown={titleKey}
      />

      {state.blocks.map((block) => (
        <div key={block.block_id} data-block-id={block.block_id} className={`block ${block.kind}${block.attrs.done === "true" ? " done" : ""}`}>
          {block.kind === "todo" && (
            <input type="checkbox" aria-label="Done" checked={block.attrs.done === "true"} onChange={() => editor.toggleDone(block.block_id)} />
          )}
          {block.kind === "attachment" ? (
            <Attachment editor={editor} block={block} media={state.media[block.block_id]} />
          ) : (
            <AutoTextarea
              data-focus-id={block.block_id}
              className={block.kind}
              value={block.text}
              placeholder={block.kind === "heading" ? "Heading" : block.kind === "todo" ? "To-do" : block.kind === "code" ? "Code" : ""}
              aria-label={block.kind}
              spellCheck={block.kind !== "code"}
              onChange={(e) => editor.editBlock(block.block_id, e.target.value, e.target.selectionStart)}
              onKeyDown={(e) => blockKey(block, e)}
            />
          )}
          <div className="tools">
            {block.kind !== "attachment" && (
              <select aria-label="Block type" value={block.kind} onChange={(e) => editor.setKind(block.block_id, e.target.value as BlockKind)}>
                {KINDS.map(([kind, label]) => (
                  <option key={kind} value={kind}>
                    {label}
                  </option>
                ))}
              </select>
            )}
            <button className="icon" aria-label="Delete block" title="Delete block" onClick={() => editor.removeBlock(block.block_id)}>
              ×
            </button>
          </div>
        </div>
      ))}

      {state.attaching > 0 && <p className="muted">Encrypting {state.attaching === 1 ? "file" : `${state.attaching} files`}…</p>}

      <button className="tail" aria-label="Add text at the end" onClick={() => editor.appendBlock()} />
    </div>
  );
}
