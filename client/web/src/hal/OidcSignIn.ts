// Sign-in at the server's identity provider (OpenID Connect, e.g. Keycloak).
//
// The authorization code flow with PKCE, for a public client:
//
//   1. the notes server issues a nonce,
//   2. the browser goes to the provider's login page,
//   3. the provider sends it back here with a code in the URL fragment,
//   4. the code and the PKCE verifier are traded for an ID token.
//
// The ID token is the only thing kept, in memory, and only to hand it to the
// notes server once. The server verifies its signature, audience and nonce;
// nothing in this file is trusted by it. Across the redirect only the PKCE
// verifier, the state and what the user had typed that is not secret are
// stored, in sessionStorage, and removed on return.

export interface Provider {
  id: string;
  issuer: string;
  client_id: string;
  scopes: string[];
}

export type Enrollment = "invite" | "oidc" | "either";

/** What `/v1/meta` says about signing in. */
export interface SignInOptions {
  enrollment: Enrollment;
  providers: Provider[];
}

/** A finished sign-in. `idToken` is single use. */
export interface Login {
  provider: string;
  idToken: string;
  /** Who signed in, for display only. */
  name: string;
}

/** What the welcome screen showed before the browser left for the login page. Nothing secret. */
export interface Draft {
  mode: "new" | "recover";
  deviceName: string;
  accountId: string;
}

interface Pending {
  provider: Provider;
  state: string;
  verifier: string;
  redirectUri: string;
  draft: Draft;
}

interface Endpoints {
  authorization: string;
  token: string;
}

export class SignInFailure extends Error {}

export class OidcSignIn {
  private static readonly STORAGE_KEY = "notes.oidc.pending";

  public constructor(private readonly serverUrl: string) {}

  /** Where the provider sends the browser back to: this page, without query or fragment. */
  private static get redirectUri(): string {
    return window.location.origin + window.location.pathname;
  }

  private static base64Url(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  private static random(length: number): string {
    return OidcSignIn.base64Url(crypto.getRandomValues(new Uint8Array(length)));
  }

  private static async json(response: Response): Promise<Record<string, unknown>> {
    const body: unknown = await response.json().catch(() => null);
    return body !== null && typeof body === "object" ? (body as Record<string, unknown>) : {};
  }

  /** The claim of an ID token that names the user. Not verified here: it is only shown. */
  private static nameIn(idToken: string): string {
    try {
      const payload = idToken.split(".")[1] ?? "";
      const binary = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
      const claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)))) as Record<string, unknown>;
      for (const claim of ["preferred_username", "email", "name"]) {
        const value = claims[claim];
        if (typeof value === "string" && value) return value.slice(0, 80);
      }
    } catch {
      // Fall through: the name is decoration.
    }
    return "your account";
  }

  /** Which sign-in the server offers. An unreachable server offers the invite code only. */
  public async options(): Promise<SignInOptions> {
    try {
      const response = await fetch(`${this.serverUrl}/v1/meta`, {
        cache: "no-store",
      });
      const auth = (await OidcSignIn.json(response)).auth as { enrollment?: unknown; oidc?: unknown } | undefined;
      const enrollment: Enrollment = auth?.enrollment === "oidc" || auth?.enrollment === "either" ? auth.enrollment : "invite";
      const providers = (Array.isArray(auth?.oidc) ? auth.oidc : []).filter(
        (p): p is Provider => typeof p?.id === "string" && typeof p.issuer === "string" && typeof p.client_id === "string" && Array.isArray(p.scopes),
      );
      return { enrollment, providers };
    } catch {
      return { enrollment: "invite", providers: [] };
    }
  }

  /**
   * The provider's endpoints, from its discovery document. They must be on
   * the issuer's own origin: nothing else is allowed by the page's policy,
   * and a code must never be sent anywhere else.
   */
  private async endpoints(provider: Provider): Promise<Endpoints> {
    const issuer = provider.issuer.replace(/\/$/, "");
    const response = await fetch(`${issuer}/.well-known/openid-configuration`, {
      cache: "no-store",
      credentials: "omit",
    });
    if (!response.ok) throw new SignInFailure("The sign-in service cannot be reached.");
    const document = await OidcSignIn.json(response);
    const { authorization_endpoint: authorization, token_endpoint: token } = document;
    const origin = new URL(issuer).origin;
    const own = (url: unknown): url is string => typeof url === "string" && new URL(url).origin === origin;
    if (document.issuer !== provider.issuer || !own(authorization) || !own(token)) {
      throw new SignInFailure("The sign-in service answered with something unexpected.");
    }
    return { authorization, token };
  }

  /** Leaves for the provider's login page. Resolves only if the browser does not navigate. */
  public async begin(provider: Provider, draft: Draft): Promise<void> {
    const nonceResponse = await fetch(`${this.serverUrl}/v1/auth/oidc/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider: provider.id }),
    });
    const nonce = (await OidcSignIn.json(nonceResponse)).nonce;
    if (!nonceResponse.ok || typeof nonce !== "string") throw new SignInFailure("The server did not start the sign-in. Try again in a minute.");
    const endpoints = await this.endpoints(provider);

    const verifier = OidcSignIn.random(32);
    const challenge = OidcSignIn.base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    const pending: Pending = {
      provider,
      state: OidcSignIn.random(16),
      verifier,
      redirectUri: OidcSignIn.redirectUri,
      draft,
    };
    sessionStorage.setItem(OidcSignIn.STORAGE_KEY, JSON.stringify(pending));

    const url = new URL(endpoints.authorization);
    url.search = new URLSearchParams({
      response_type: "code",
      // The code comes back in the fragment, which is not sent to any server.
      response_mode: "fragment",
      client_id: provider.client_id,
      redirect_uri: pending.redirectUri,
      scope: provider.scopes.join(" "),
      state: pending.state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();
    window.location.assign(url);
  }

  /**
   * Call once when the page loads. Returns the login and what the user had
   * typed if the browser just came back from the provider, `null` if this
   * is an ordinary page load.
   */
  public async finish(): Promise<{ login: Login; draft: Draft } | { failure: string; draft: Draft } | null> {
    const stored = sessionStorage.getItem(OidcSignIn.STORAGE_KEY);
    const answer = new URLSearchParams(window.location.hash.slice(1));
    if (!answer.has("state")) return null;
    // The code is single use: take it out of the address bar and the history.
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    sessionStorage.removeItem(OidcSignIn.STORAGE_KEY);
    if (!stored) return null;
    const pending = JSON.parse(stored) as Pending;
    // An answer that this page did not ask for is ignored.
    if (answer.get("state") !== pending.state) return null;
    try {
      const login = await this.redeem(pending, answer);
      return { login, draft: pending.draft };
    } catch (error) {
      return {
        failure: error instanceof SignInFailure ? error.message : "The sign-in did not finish. Try again.",
        draft: pending.draft,
      };
    }
  }

  private async redeem(pending: Pending, answer: URLSearchParams): Promise<Login> {
    const code = answer.get("code");
    if (answer.has("error") || !code) {
      throw new SignInFailure(answer.get("error") === "access_denied" ? "The sign-in was cancelled." : "The sign-in service refused the sign-in.");
    }
    // Providers that name themselves in the answer (RFC 9207) must name the right one.
    const issuer = answer.get("iss");
    if (issuer !== null && issuer !== pending.provider.issuer) throw new SignInFailure("The answer came from a different sign-in service.");

    const endpoints = await this.endpoints(pending.provider);
    const response = await fetch(endpoints.token, {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: pending.redirectUri,
        client_id: pending.provider.client_id,
        code_verifier: pending.verifier,
      }),
    });
    const idToken = (await OidcSignIn.json(response)).id_token;
    if (!response.ok || typeof idToken !== "string") throw new SignInFailure("The sign-in service did not confirm the sign-in.");
    return {
      provider: pending.provider.id,
      idToken,
      name: OidcSignIn.nameIn(idToken),
    };
  }
}
