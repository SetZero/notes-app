// The HAL adapter for browsers: the one object handed to the core.
//
// The method names are the ones the WebAssembly side calls (see
// wasm/src/lib.rs); each just forwards to the port that owns the job.

import { BrowserNetworkMonitor, FetchHttpTransport, IndexedDbFileStore, SystemTimeSource, WebCryptoEntropy, WebCryptoSecureStore } from "./adapters";
import { IndexedDb } from "./IndexedDb";
import type { Bytes, Entropy, FileStore, HttpResponseData, HttpTransport, NetworkMonitor, SecureStore, TimeSource } from "./ports";

export class WebHal {
  public constructor(
    private readonly transport: HttpTransport,
    private readonly files: FileStore,
    private readonly secrets: SecureStore,
    private readonly time: TimeSource,
    private readonly network: NetworkMonitor,
    private readonly entropy: Entropy,
  ) {}

  /** The adapter with the real browser implementations. */
  public static async create(): Promise<WebHal> {
    const db = await IndexedDb.open();
    return new WebHal(
      new FetchHttpTransport(),
      new IndexedDbFileStore(db),
      new WebCryptoSecureStore(db),
      new SystemTimeSource(),
      new BrowserNetworkMonitor(),
      new WebCryptoEntropy(),
    );
  }

  public http(method: string, url: string, headers: [string, string][], body?: Bytes): Promise<HttpResponseData> {
    return this.transport.send(method, url, headers, body);
  }

  public fileRead(name: string): Promise<Bytes | null> {
    return this.files.read(name);
  }

  public fileWrite(name: string, data: Bytes): Promise<void> {
    return this.files.write(name, data);
  }

  public fileRemove(name: string): Promise<void> {
    return this.files.remove(name);
  }

  public fileList(prefix: string): Promise<string[]> {
    return this.files.list(prefix);
  }

  public secretGet(name: string): Promise<Bytes | null> {
    return this.secrets.get(name);
  }

  public secretPut(name: string, data: Bytes): Promise<void> {
    return this.secrets.put(name, data);
  }

  public secretRemove(name: string): Promise<void> {
    return this.secrets.remove(name);
  }

  public nowMs(): number {
    return this.time.nowMs();
  }

  public isOnline(): boolean {
    return this.network.isOnline();
  }

  public fillRandom(buffer: Bytes): void {
    this.entropy.fill(buffer);
  }
}
