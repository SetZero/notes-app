// A small promise wrapper around the one IndexedDB database of the app.

export type StoreName = "files" | "secrets" | "keys";

export class IndexedDb {
  private static readonly NAME = "notes-app";
  private static readonly VERSION = 1;
  private static readonly STORES: readonly StoreName[] = ["files", "secrets", "keys"];

  private constructor(private readonly db: IDBDatabase) {
    // Another tab wants to upgrade or delete the database: let it.
    this.db.onversionchange = () => this.db.close();
  }

  public static open(): Promise<IndexedDb> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(IndexedDb.NAME, IndexedDb.VERSION);
      request.onupgradeneeded = () => {
        for (const name of IndexedDb.STORES) request.result.createObjectStore(name);
      };
      request.onsuccess = () => resolve(new IndexedDb(request.result));
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error("the notes database is in use by an older tab"));
    });
  }

  /** Runs one request in its own transaction and resolves when it is committed. */
  private run<T>(store: StoreName, mode: IDBTransactionMode, operation: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(store, mode);
      const request = operation(transaction.objectStore(store));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error ?? new Error("storage transaction aborted"));
    });
  }

  public get<T>(store: StoreName, key: string): Promise<T | undefined> {
    return this.run(store, "readonly", (s) => s.get(key) as IDBRequest<T | undefined>);
  }

  public async put(store: StoreName, key: string, value: unknown): Promise<void> {
    await this.run(store, "readwrite", (s) => s.put(value, key));
  }

  public async delete(store: StoreName, key: string): Promise<void> {
    await this.run(store, "readwrite", (s) => s.delete(key));
  }

  public async keys(store: StoreName, prefix: string): Promise<string[]> {
    const range = prefix ? IDBKeyRange.bound(prefix, prefix + "￿") : undefined;
    return (await this.run(store, "readonly", (s) => s.getAllKeys(range))) as string[];
  }
}
