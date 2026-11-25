import {
  IconAspectRatio,
  IconFloatLeft,
  IconFloatRight,
  IconLayoutAlignCenter,
  IconLayoutAlignLeft,
  IconLayoutAlignRight,
  IconTag,
  IconTagOff,
  IconTrash,
} from "@tabler/icons-react";
import { useEffect, useRef, type DragEvent, type PointerEvent, type ReactNode } from "react";
import type { Block } from "../core";
import type { EditorViewModel, Media } from "../viewmodels/EditorViewModel";

/** The drag-and-drop type for moving a block inside a note. */
export const BLOCK_DRAG_TYPE = "application/x-notes-block";

/**
 * Where a picture or video sits. The first three keep it on a line of its
 * own; with the last two the blocks that follow flow beside it.
 */
export type Placement = "left" | "center" | "right" | "wrap-left" | "wrap-right";

/** The width a picture gets when text flows around it and none was chosen. */
const WRAP_WIDTH = 40;

const ICON = { size: 18, stroke: 1.75, "aria-hidden": true } as const;

const PLACEMENTS: [Placement, string, ReactNode][] = [
  ["left", "Align left", <IconLayoutAlignLeft {...ICON} />],
  ["center", "Centre", <IconLayoutAlignCenter {...ICON} />],
  ["right", "Align right", <IconLayoutAlignRight {...ICON} />],
  ["wrap-left", "Left, text flows around it", <IconFloatLeft {...ICON} />],
  ["wrap-right", "Right, text flows around it", <IconFloatRight {...ICON} />],
];

function readableSize(bytes: number): string {
  if (!Number.isFinite(bytes)) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function isVisual(media: Media | undefined): boolean {
  return media?.kind === "image" || media?.kind === "video";
}

export function placementOf(block: Block): Placement {
  if (block.attrs.wrap === "left") return "wrap-left";
  if (block.attrs.wrap === "right") return "wrap-right";
  return block.attrs.align === "center" || block.attrs.align === "right" ? block.attrs.align : "left";
}

export function wraps(placement: Placement): boolean {
  return placement === "wrap-left" || placement === "wrap-right";
}

/** Width in percent of the note's width; `null` means the file's own size. */
export function widthOf(block: Block): number | null {
  const width = Number(block.attrs.width);
  if (Number.isFinite(width) && width >= 10 && width <= 100) return width;
  return wraps(placementOf(block)) ? WRAP_WIDTH : null;
}

interface Props {
  editor: EditorViewModel;
  block: Block;
  media: Media | undefined;
  /** The width while the corner is being dragged; it is saved on release. */
  draft: number | null;
  onDraft: (width: number | null) => void;
}

/** An image, audio or video player, or a download link, for one attachment block. */
export function Attachment({ editor, block, media, draft, onDraft }: Props) {
  const figure = useRef<HTMLElement>(null);

  // Decrypt when the block is first shown, and again after a failed attempt
  // was cleared by a sync.
  useEffect(() => {
    if (!media) editor.loadMedia(block.block_id);
  }, [editor, block.block_id, media]);

  const name = block.text || "Attachment";
  const size = readableSize(Number(block.attrs.size));
  const placement = placementOf(block);
  const visual = isVisual(media);
  const wrapped = visual && wraps(placement);
  const width = draft ?? widthOf(block);
  const hidden = block.attrs.caption === "hidden";

  const startDrag = (event: DragEvent<HTMLElement>) => {
    event.dataTransfer.setData(BLOCK_DRAG_TYPE, block.block_id);
    event.dataTransfer.effectAllowed = "move";
  };

  const resize = (event: PointerEvent<HTMLSpanElement>) => {
    const box = figure.current;
    const note = box?.closest<HTMLElement>(".blocks");
    if (!box || !note || !(event.buttons & 1)) return;
    const rect = box.getBoundingClientRect();
    // The corner follows the pointer; a centred picture grows on both sides.
    const pixels =
      placement === "right" || placement === "wrap-right"
        ? rect.right - event.clientX
        : placement === "center"
          ? 2 * (event.clientX - (rect.left + rect.width / 2))
          : event.clientX - rect.left;
    onDraft(Math.round(Math.min(100, Math.max(10, (pixels / note.clientWidth) * 100))));
  };

  const endResize = () => {
    if (draft !== null) editor.setDisplay(block.block_id, { width: String(draft) });
    onDraft(null);
  };

  const place = (next: Placement) => {
    const wrap = next === "wrap-left" ? "left" : next === "wrap-right" ? "right" : "";
    editor.setDisplay(block.block_id, {
      wrap,
      align: wrap || next === "left" ? "" : next,
    });
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

  // When text flows around it, the row carries the width and the figure fills the row.
  const sized = visual && width !== null;
  return (
    <figure
      ref={figure}
      className={`media align-${placement}${visual ? " visual" : ""}${sized ? " sized" : ""}`}
      style={sized && !wrapped ? { width: `${width}%` } : undefined}
    >
      {body}
      {visual && media?.url && (
        <div className="toolbar" role="toolbar" aria-label="Picture">
          {PLACEMENTS.map(([value, label, glyph]) => (
            <button key={value} aria-label={label} title={label} aria-pressed={placement === value} onClick={() => place(value)}>
              {glyph}
            </button>
          ))}
          <span className="rule" />
          <button
            aria-label="Back to the original size"
            title="Back to the original size"
            disabled={!block.attrs.width}
            onClick={() => editor.setDisplay(block.block_id, { width: "" })}
          >
            <IconAspectRatio {...ICON} />
          </button>
          <button
            aria-label={hidden ? "Show the file name below" : "Hide the file name below"}
            title={hidden ? "Show the file name below" : "Hide the file name below"}
            aria-pressed={!hidden}
            onClick={() =>
              editor.setDisplay(block.block_id, {
                caption: hidden ? "" : "hidden",
              })
            }
          >
            {hidden ? <IconTagOff {...ICON} /> : <IconTag {...ICON} />}
          </button>
          <span className="rule" />
          <button aria-label="Delete" title="Delete" onClick={() => editor.removeBlock(block.block_id)}>
            <IconTrash {...ICON} />
          </button>
        </div>
      )}
      {visual && media?.url && (
        <span
          className="resize"
          role="separator"
          aria-label="Drag to resize"
          title="Drag to resize"
          onPointerDown={(e) => e.currentTarget.setPointerCapture(e.pointerId)}
          onPointerMove={resize}
          onPointerUp={endResize}
          onPointerCancel={() => onDraft(null)}
        />
      )}
      {!hidden && (
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

/** The controls beside an attachment that is not a picture: only its caption. */
export function AttachmentTools({ editor, block, media }: { editor: EditorViewModel; block: Block; media: Media | undefined }) {
  // A plain file has nothing but its name to show.
  if (!media || media.kind === "file") return null;
  const hidden = block.attrs.caption === "hidden";
  const label = hidden ? "Show the file name below" : "Hide the file name below";
  return (
    <button
      className="icon"
      aria-pressed={!hidden}
      aria-label={label}
      title={label}
      onClick={() => editor.setDisplay(block.block_id, { caption: hidden ? "" : "hidden" })}
    >
      {hidden ? <IconTagOff {...ICON} /> : <IconTag {...ICON} />}
    </button>
  );
}
