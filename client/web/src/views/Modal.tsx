import { useEffect, useRef, type ReactNode } from "react";

/** A modal dialog, using the browser's own <dialog> (focus trap, Esc, backdrop). */
export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (dialog && !dialog.open) dialog.showModal();
    return () => dialog?.close();
  }, []);

  return (
    <dialog ref={ref} onClose={onClose} aria-label={title}>
      <header>
        <h2>{title}</h2>
        <button className="icon" aria-label="Close" onClick={onClose}>
          ×
        </button>
      </header>
      {children}
    </dialog>
  );
}
