// The web implementations of the six HAL ports.

import { IndexedDb } from "./IndexedDb";
import type { Bytes, Entropy, FileStore, HttpResponseData, HttpTransport, NetworkMonitor, SecureStore, TimeSource } from "./ports";

export class FetchHttpTransport implements HttpTransport {
  private static readonly TIMEOUT_MS = 30000;

  public async send(method: string, url: string, headers: [string, string][], body?: Bytes): Promise<HttpResponseData> {
    const response = await fetch(url, {
      method,
      headers: Object.fromEntries(headers),
      body: body ?? undefined,
      // The device token travels in the Authorization header only; there are
      // no cookies to attach, and a redirect would leak it to another host.
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(FetchHttpTransport.TIMEOUT_MS),
    });
    return {
      status: response.status,
      headers: [...response.headers],
      body: new Uint8Array(await response.arrayBuffer()),
    };
  }
}

export class IndexedDbFileStore implements FileStore {
  public constructor(private readonly db: IndexedDb) {}

  public async read(name: string): Promise<Bytes | null> {
    return (await this.db.get<Bytes>("files", name)) ?? null;
  }

  public write(name: string, data: Bytes): Promise<void> {
    return this.db.put("files", name, data);
  }

  public remove(name: string): Promise<void> {
    return this.db.delete("files", name);
  }

  public list(prefix: string): Promise<string[]> {
    return this.db.keys("files", prefix);
  }
}

interface WrappedSecret {
  iv: Bytes;
  data: Bytes;
}

/**
 * Secrets are stored encrypted with an AES-GCM key that is created as
 * non-extractable: the browser will use it for this page, but never hands out
 * its bytes, not even to this script. That keeps the account key and the
 * device token out of plain storage dumps and backups. It does not protect
 * against script running in this page, which is what the
 * Content-Security-Policy is for.
 */
export class WebCryptoSecureStore implements SecureStore {
  private static readonly WRAPPING_KEY = "secret-wrapping-key";
  private wrappingKey: CryptoKey | undefined;

  public constructor(private readonly db: IndexedDb) {}

  private async key(): Promise<CryptoKey> {
    if (this.wrappingKey) return this.wrappingKey;
    this.wrappingKey = await this.db.get<CryptoKey>("keys", WebCryptoSecureStore.WRAPPING_KEY);
    if (!this.wrappingKey) {
      const created = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      await this.db.put("keys", WebCryptoSecureStore.WRAPPING_KEY, created);
      this.wrappingKey = created;
    }
    return this.wrappingKey;
  }

  public async get(name: string): Promise<Bytes | null> {
    const stored = await this.db.get<WrappedSecret>("secrets", name);
    if (!stored) return null;
    try {
      return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: stored.iv }, await this.key(), stored.data));
    } catch {
      // The wrapping key is gone or the record was altered: no session.
      return null;
    }
  }

  public async put(name: string, data: Bytes): Promise<void> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await this.key(), data);
    const record: WrappedSecret = { iv, data: new Uint8Array(encrypted) };
    await this.db.put("secrets", name, record);
  }

  public remove(name: string): Promise<void> {
    return this.db.delete("secrets", name);
  }
}

export class SystemTimeSource implements TimeSource {
  public nowMs(): number {
    return Date.now();
  }
}

export class BrowserNetworkMonitor implements NetworkMonitor {
  public isOnline(): boolean {
    return navigator.onLine;
  }
}

export class WebCryptoEntropy implements Entropy {
  public fill(buffer: Bytes): void {
    crypto.getRandomValues(buffer);
  }
}
