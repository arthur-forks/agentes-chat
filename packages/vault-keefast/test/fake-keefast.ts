/**
 * A fake keefast Headless host speaking the Gateway API (`/gateway/v1/`, ADR 0190), as a `fetch`. Its refusals put
 * the token and the values it holds into keefast's own `message` on purpose, and its network failures carry them in
 * the thrown error: what comes out of the source must never show them.
 */

export const FAKE_TOKEN = "kfg_fake-gateway-token-NEVER-SHOWN-0001";
export const FAKE_BASE = "https://keefast.acme.example";

export interface FakeEntry {
  ref: string;
  kind: "login" | "key";
  title: string;
  username?: string;
  websites?: { url: string; match: "exact" }[];
  keyName?: string;
  updatedAt?: string;
  value: string;
  /** In the pairing's own subgroup, where it may change logins. */
  own?: boolean;
}

export interface FakeRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
  redirect: RequestInit["redirect"];
  signal: AbortSignal | undefined;
}

export interface FakeKeefast {
  fetch: typeof fetch;
  state: {
    entries: FakeEntry[];
    canWrite: boolean;
    locked: boolean;
    down: boolean;
    revision: number;
    /** Stray fields put on every listed item, which keefast never sends but a client must not pass on. */
    leak: boolean;
  };
  requests: FakeRequest[];
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

export function createFakeKeefast(entries: FakeEntry[], options: { canWrite?: boolean } = {}): FakeKeefast {
  const state: FakeKeefast["state"] = {
    entries: entries.map((e) => ({ ...e })),
    canWrite: options.canWrite ?? true,
    locked: false,
    down: false,
    revision: 1,
    leak: false,
  };
  const requests: FakeRequest[] = [];
  const secrets = () => `${FAKE_TOKEN} ${state.entries.map((e) => e.value).join(" ")}`;
  const refuse = (status: number, code: string) => json(status, { code, message: `refused ${code}: ${secrets()}` });
  const itemOf = (e: FakeEntry) => ({
    ref: e.ref,
    kind: e.kind,
    title: e.title,
    ...(e.updatedAt ? { updatedAt: e.updatedAt } : {}),
    ...(e.kind === "login" ? { username: e.username, websites: e.websites ?? [] } : { keyName: e.keyName }),
    ...(state.leak ? { password: e.value, notes: `notes ${e.value}`, value: e.value } : {}),
  });

  const handler = async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((value, name) => {
      headers[name] = value;
    });
    const body = typeof init.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    const method = (init.method ?? "GET").toUpperCase();
    requests.push({
      method,
      path: url.pathname,
      headers,
      body,
      redirect: init.redirect,
      signal: init.signal ?? undefined,
    });
    if (init.signal?.aborted) throw new DOMException(`aborted ${secrets()}`, "AbortError");
    if (state.down) throw new TypeError(`connect ECONNREFUSED 10.0.0.9:443 (${secrets()})`);
    if (url.origin !== FAKE_BASE || !url.pathname.startsWith("/gateway/v1/")) return refuse(404, "not_found");
    if (headers.authorization !== `Bearer ${FAKE_TOKEN}`) return refuse(401, "unauthorized");
    if (state.locked) return refuse(423, "locked");
    const path = url.pathname.slice("/gateway/v1".length);
    const etag = `"rev-${state.revision}"`;

    if (method === "GET" && path === "/whoami") {
      return json(200, {
        vault: "Agents",
        pairing: "agentes",
        subgroups: ["agentes", "shared"],
        canWrite: state.canWrite,
      });
    }
    if (method === "GET" && path === "/items") {
      if (headers["if-none-match"] === etag) return new Response(null, { status: 304, headers: { etag } });
      return json(200, { items: state.entries.map(itemOf) }, { etag });
    }
    const resolve = /^\/items\/([^/]+)\/resolve$/.exec(path);
    if (method === "POST" && resolve) {
      const entry = state.entries.find((e) => e.ref === resolve[1]);
      if (!entry) return refuse(404, "not_found");
      return json(200, { value: entry.value });
    }
    if (method === "POST" && path === "/logins") {
      if (!state.canWrite) return refuse(403, "read_only");
      const b = body as { title?: string; username?: string; password?: string; website?: string };
      if (!b?.title || !b.password) return refuse(400, "invalid_input");
      if (b.website && !b.website.startsWith("https://")) return refuse(400, "invalid_input");
      const entry: FakeEntry = {
        ref: `00000000-0000-4000-8000-${String(state.entries.length + 1).padStart(12, "0")}`,
        kind: "login",
        title: b.title,
        ...(b.username ? { username: b.username } : {}),
        ...(b.website ? { websites: [{ url: b.website, match: "exact" as const }] } : {}),
        value: b.password,
        own: true,
      };
      state.entries.push(entry);
      state.revision++;
      return json(201, itemOf(entry));
    }
    const change = /^\/logins\/([^/]+)$/.exec(path);
    if (method === "PATCH" && change) {
      if (!state.canWrite) return refuse(403, "read_only");
      const entry = state.entries.find((e) => e.ref === change[1]);
      if (entry?.kind !== "login") return refuse(404, "not_found");
      if (!entry.own) return refuse(403, "not_writable");
      const b = body as { username?: string; password?: string };
      if (b.username !== undefined) entry.username = b.username;
      if (b.password !== undefined) entry.value = b.password;
      state.revision++;
      return json(200, itemOf(entry));
    }
    return refuse(404, "not_found");
  };
  return { fetch: handler as typeof fetch, state, requests };
}
