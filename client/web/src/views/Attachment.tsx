import { useEffect, useRef, useState, type DragEvent, type PointerEvent } from "react";
import type { Block } from "../core";
import type { EditorViewModel, Media } from "../viewmodels/EditorViewModel";

/** The drag-and-drop type for moving a block inside a note. */
export const BLOCK_DRAG_TYPE = "application/x-notes-block";

export type Align = "left" | "center" | "right";

function readableSize(bytes: number): string {
  if (!Number.isFinite(bytes)) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function alignOf(block: Block): Align {
  return block.attrs.align === "center" || block.attrs.align === "right" ? block.attrs.align : "left";
}

/** Width in percent of the note's width; `null` means the file's own size. */
function widthOf(block: Block): number | null {
  const width = Number(block.attrs.width);
  return Number.isFinite(width) && width >= 10 && width <= 100 ? width : null;
}

/** An image, audio or video player, or a download link, for one attachment block. */
export function Attachment({ editor, block, media }: { editor: EditorViewModel; block: Block; media: Media | undefined }) {
  const figure = useRef<HTMLElement>(null);
  // While the corner is being dragged, the width lives here; it is saved
  // once, when the pointer is released.
  const [draft, setDraft] = useState<number | null>(null);

  // Decrypt when the block is first shown, and again after a failed attempt
  // was cleared by a sync.
  useEffect(() => {
    if (!media) editor.loadMedia(block.block_id);
  }, [editor, block.block_id, media]);

  const name = block.text || "Attachment";
  const size = readableSize(Number(block.attrs.size));
  const align = alignOf(block);
  const visual = media?.kind === "image" || media?.kind === "video";
  const width = draft ?? widthOf(block);

  const startDrag = (event: DragEvent<HTMLElement>) => {
    event.dataTransfer.setData(BLOCK_DRAG_TYPE, block.block_id);
    event.dataTransfer.effectAllowed = "move";
  };

  const resize = (event: PointerEvent<HTMLSpanElement>) => {
    const box = figure.current;
    const row = box?.parentElement;
    if (!box || !row || !(event.buttons & 1)) return;
    const rect = box.getBoundingClientRect();
    // The corner follows the pointer; a centred picture grows on both sides.
    const pixels =
      align === "right" ? rect.right - event.clientX : align === "center" ? 2 * (event.clientX - (rect.left + rect.width / 2)) : event.clientX - rect.left;
    setDraft(Math.round(Math.min(100, Math.max(10, (pixels / row.clientWidth) * 100))));
  };

  const endResize = () => {
    if (draft !== null) editor.setDisplay(block.block_id, { width: String(draft) });
    setDraft(null);
  };

  let body = <p className="muted">Decrypting…</p>;
  if (media?.problem) {
    body = <p className="problem">{media.problem}</p>;
  } else if (media?.url) {
    if (media.kind === "image") body = <img src={media.url} alt={name} draggable onDragStart={startDrag} />;
    else if (media.kind === "audio") body = <audio src={media.url} controls preload="metadata" />;
    else if (media.kind === "video") body = <video src={media.url} controls preload="metadata" />;
    else body = <></>;
  }

  return (
    <figure ref={figure} className={`media align-${align}${visual ? " visual" : ""}${visual && width !== null ? " sized" : ""}`} style={visual && width !== null ? { width: `${width}%` } : undefined}>
      {body}
      {visual && media?.url && (
        <span
          className="resize"
          role="separator"
          aria-label="Drag to resize"
          title="Drag to resize"
          onPointerDown={(e) => e.currentTarget.setPointerCapture(e.pointerId)}
          onPointerMove={resize}
          onPointerUp={endResize}
          onPointerCancel={() => setDraft(null)}
        />
      )}
      {block.attrs.caption !== "hidden" && (
        <figcaption>
          {media?.url ? (
            <a href={media.url} download={name}>
              {name}
            </a>
          ) : (
            name
          )}
          {size && <span className="muted"> · {size}</span>}
        </figcaption>
      )}
    </figure>
  );
}

/** The controls of an attachment block: alignment, size and caption. */
export function AttachmentTools({ editor, block, media }: { editor: EditorViewModel; block: Block; media: Media | undefined }) {
  const visual = media?.kind === "image" || media?.kind === "video";
  const hidden = block.attrs.caption === "hidden";
  return (
    <>
      {visual && (
        <select aria-label="Alignment" value={alignOf(block)} onChange={(e) => editor.setDisplay(block.block_id, { align: e.target.value === "left" ? "" : e.target.value })}>
          <option value="left">Left</option>
          <option value="center">Centre</option>
          <option value="right">Right</option>
        </select>
      )}
      {visual && block.attrs.width && (
        <button className="icon small" title="Back to the original size" onClick={() => editor.setDisplay(block.block_id, { width: "" })}>
          1:1
        </button>
      )}
      {/* A plain file has nothing but its name to show. */}
      {media?.kind !== "file" && (
        <button
          className="icon small"
          aria-pressed={hidden}
          title={hidden ? "Show the file name below" : "Hide the file name below"}
          onClick={() => editor.setDisplay(block.block_id, { caption: hidden ? "" : "hidden" })}
        >
          {hidden ? "Show name" : "Hide name"}
        </button>
      )}
    </>
  );
}
