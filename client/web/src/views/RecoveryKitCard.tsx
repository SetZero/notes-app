import type { RecoveryKit } from "../core";

/** The account ID and the 24 words, laid out for copying onto paper. */
export function RecoveryKitCard({ kit }: { kit: RecoveryKit }) {
  const words = kit.phrase.split(" ");
  return (
    <div className="kit">
      <dl>
        <dt>Server</dt>
        <dd>{kit.server_url}</dd>
        <dt>Account ID</dt>
        <dd className="mono">{kit.account_id}</dd>
      </dl>
      <ol className="words" translate="no">
        {words.map((word, index) => (
          <li key={index}>{word}</li>
        ))}
      </ol>
    </div>
  );
}
