import qrcode from "qrcode-generator";
import { useMemo } from "react";

/** How many modules of white surround the code; scanners need four. */
const QUIET = 4;

/** `text` as a QR code. Always dark on white, whatever the theme: cameras expect that. */
export function QrCode({ text, label }: { text: string; label: string }) {
  const { size, path } = useMemo(() => {
    const code = qrcode(0, "M");
    code.addData(text);
    code.make();
    const count = code.getModuleCount();
    let d = "";
    for (let row = 0; row < count; row++) {
      for (let column = 0; column < count; column++) {
        if (code.isDark(row, column)) d += `M${column + QUIET} ${row + QUIET}h1v1h-1z`;
      }
    }
    return { size: count + 2 * QUIET, path: d };
  }, [text]);

  return (
    <svg className="qr" viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label} shapeRendering="crispEdges">
      <rect width={size} height={size} fill="#ffffff" />
      <path d={path} fill="#000000" />
    </svg>
  );
}
