// The six ports of the hardware abstraction layer, as the shared core
// defines them (common/core/src/hal.rs). The web adapter implements each of
// them in its own class; nothing in this folder knows what a note is.

export type Bytes = Uint8Array<ArrayBuffer>;

export interface HttpResponseData {
  status: number;
  headers: [string, string][];
  body: Bytes;
}

/** HTTPS requests. No cookies, no redirects. */
export interface HttpTransport {
  send(method: string, url: string, headers: [string, string][], body?: Bytes): Promise<HttpResponseData>;
}

/** Named byte blobs that survive a restart. Only ciphertext is stored here. */
export interface FileStore {
  read(name: string): Promise<Bytes | null>;
  write(name: string, data: Bytes): Promise<void>;
  remove(name: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

/** The best protected storage the platform has: account key and device token. */
export interface SecureStore {
  get(name: string): Promise<Bytes | null>;
  put(name: string, data: Bytes): Promise<void>;
  remove(name: string): Promise<void>;
}

export interface TimeSource {
  /** Milliseconds since the Unix epoch. */
  nowMs(): number;
}

export interface NetworkMonitor {
  isOnline(): boolean;
}

export interface Entropy {
  /** Fills the buffer with cryptographically secure random bytes. */
  fill(buffer: Bytes): void;
}
