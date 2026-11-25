// Listens to the server's "something changed" stream.
//
// EventSource cannot send an Authorization header, so the stream is read with
// fetch. A notification carries no data; it only means "sync now".

export interface EventsRequest {
  url: string;
  authorization: string;
}

export class ChangeListener {
  private static readonly FIRST_PAUSE_MS = 1000;
  private static readonly LONGEST_PAUSE_MS = 60000;
  private static readonly MAX_BUFFER = 65536;

  private stopped = true;
  private controller: AbortController | null = null;

  /**
   * @param request   where to connect; asked again before every attempt
   * @param onChange  called for every notification, and after every
   *                  (re)connect because changes may have been missed
   */
  public constructor(
    private readonly request: () => EventsRequest,
    private readonly onChange: () => void,
  ) {}

  public start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    void this.run();
  }

  public stop(): void {
    this.stopped = true;
    this.controller?.abort();
    this.controller = null;
  }

  private async run(): Promise<void> {
    let pause = ChangeListener.FIRST_PAUSE_MS;
    while (!this.stopped) {
      try {
        const connected = await this.listenOnce();
        if (connected === "unauthorized") return; // signed out or revoked: sync reports it
        pause = ChangeListener.FIRST_PAUSE_MS;
      } catch {
        // Offline, server restart, or stopped: wait and try again.
      }
      if (this.stopped) return;
      await new Promise((resolve) => setTimeout(resolve, pause));
      pause = Math.min(pause * 2, ChangeListener.LONGEST_PAUSE_MS);
    }
  }

  /** Resolves when the server ends the stream; rejects if it breaks. */
  private async listenOnce(): Promise<"ended" | "unauthorized"> {
    const { url, authorization } = this.request();
    this.controller = new AbortController();
    const response = await fetch(url, {
      headers: { authorization, accept: "text/event-stream" },
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: this.controller.signal,
    });
    if (response.status === 401) return "unauthorized";
    if (!response.ok || !response.body) throw new Error(`event stream answered ${response.status}`);
    this.onChange();

    const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
    let buffered = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return "ended";
      buffered += value;
      let end: number;
      while ((end = buffered.indexOf("\n\n")) >= 0) {
        const event = buffered.slice(0, end);
        buffered = buffered.slice(end + 2);
        if (/^event: ?changed$/m.test(event)) this.onChange();
      }
      if (buffered.length > ChangeListener.MAX_BUFFER) buffered = "";
    }
  }
}
