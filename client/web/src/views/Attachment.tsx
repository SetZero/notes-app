import { useEffect } from "react";
import type { Block } from "../core";
import type { EditorViewModel, Media } from "../viewmodels/EditorViewModel";

function readableSize(bytes: number): string {
  if (!Number.isFinite(bytes)) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** An image, audio or video player, or a download link, for one attachment block. */
export function Attachment({ editor, block, media }: { editor: EditorViewModel; block: Block; media: Media | undefined }) {
  // Decrypt when the block is first shown, and again after a failed attempt
  // was cleared by a sync.
  useEffect(() => {
    if (!media) editor.loadMedia(block.block_id);
  }, [editor, block.block_id, media]);

  const name = block.text || "Attachment";
  const size = readableSize(Number(block.attrs.size));

  let body = <p className="muted">Decrypting…</p>;
  if (media?.problem) {
    body = <p className="problem">{media.problem}</p>;
  } else if (media?.url) {
    if (media.kind === "image") body = <img src={media.url} alt={name} />;
    else if (media.kind === "audio") body = <audio src={media.url} controls preload="metadata" />;
    else if (media.kind === "video") body = <video src={media.url} controls preload="metadata" />;
    else body = <></>;
  }

  return (
    <figure className="media">
      {body}
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
    </figure>
  );
}
