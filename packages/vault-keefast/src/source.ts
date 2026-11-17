/**
 * keefast as a Vault source (ADR 0144, ADR 0190): a client of the Gateway API that `keefast-agent serve` offers a
 * Gateway pairing, under `/gateway/v1/`. keefast maps its Entries to items itself, so this client stays thin: it
 * checks the token (`whoami`), lists metadata, resolves one value when asked, and keeps or changes a login in the
 * pairing's own subgroup.
 *
 * - Every request carries the pairing's token as a bearer token and nothing else secret; the token is never in a URL.
 * - Every failure is a `VaultSourceError` in our own words. keefast's `{ code, message }` is read for its code only:
 *   its text is never stored or shown, and neither is the token or a value.
 * - keefast's `locked` (423: the host waits for `keefast-agent unlock`) is `unreachable` here, not `locked`: the
 *   engine's `locked` means a wrong master password and stops syncing until a person reconnects, while `unreachable`
 *   is tried again by itself, which is what an unlock needs (ADR 0190).
 * - A change refused for one login outside the pairing's own subgroup is `not_writable`; a pairing that may not
 *   write at all is `read_only` (ADR 0190).
 * - `list` sends the ETag of the last list it read for that connection (`If-None-Match`) and, on `304`, returns that
 *   list again: the engine still gets every item, as a sync needs, and keefast reads nothing. The list is metadata
 *   only and kept in this process's memory, a few hundred connections at most, keyed by the URL and a hash of the
 *   token so a new token never reuses an old list.
 * - The address is typed by a person. Requests go through the guarded `fetch` the server passes (public HTTPS
 *   addresses only), except to a host the server's operator listed (`VAULT_KEEFAST_PRIVATE_HOSTS`), which may resolve
 *   to a loopback, private or tailnet address and is fetched with plain `fetch`, still over HTTPS only. A redirect is
 *   never followed, from either.
 * - Every call has a deadline (60 s, as the engine's own) and stops when the engine's signal aborts.
 */
import {
  OutboundAddressError,
  readCapped,
  VAULT_READ_ONLY_CONFIG,
  type VaultConnection,
  type VaultConnectResult,
  type VaultLoginChange,
  type VaultMatch,
  type VaultNewLogin,
  type VaultSecretField,
  type VaultSource,
  type VaultSourceDescriptor,
  VaultSourceError,
  type VaultSourceErrorCode,
  type VaultSourceItem,
  vaultOrigin,
} from "@agenteschat/adapters";

export const KEEFAST_SOURCE_KIND = "keefast";

export interface KeefastSourceOptions {
  /**
   * How the server reaches a keefast host a person typed: one that connects only to public addresses
   * (`publicHttpsFetch`); tests pass a fake. An `OutboundAddressError` it throws is `invalid_input`.
   */
  fetch?: typeof fetch;
  /** How the server reaches a host on `privateHosts`: plain `fetch` by default; tests pass a fake. */
  privateFetch?: typeof fetch;
  /**
   * Host names the server's operator lets resolve to private addresses (`VAULT_KEEFAST_PRIVATE_HOSTS`), lower case.
   * Never set from anything a workspace's members type.
   */
  privateHosts?: readonly string[];
  /** The clock for `retryAt` (tests pass a fake). */
  now?: () => number;
  /** Per call; 60 s by default. */
  timeoutMs?: number;
}

const TIMEOUT_MS = 60_000;
const DEFAULT_RETRY_MS = 60_000;
const MAX_BODY_BYTES = 1024 * 1024;
/** A pairing reads the subgroups made for agents; this only stops a runaway answer. */
const MAX_LIST_BYTES = 32 * 1024 * 1024;
/** Connections whose last list is kept for `If-None-Match`; the oldest goes first. */
const MAX_KEPT_LISTS = 500;
const MAX_TITLE = 512;
const MAX_LABEL = 200;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const KEY_NAME = /^[A-Z][A-Z0-9_]*$/;

/** Our own words for every failure: keefast's text is never passed on. */
const MESSAGES = {
  url: "Type the address of your keefast host, starting with https://.",
  token: "Paste the token `keefast-agent pairing add --gateway` printed.",
  connection: "This connection is missing settings. Connect it again.",
  privateHost:
    "This address is on a private or internal network, which this server doesn't connect to. Use the host's public HTTPS address, or ask whoever runs this server to list it in VAULT_KEEFAST_PRIVATE_HOSTS.",
  notFound: "This item is no longer in the subgroups the pairing reads.",
  readOnly: "This pairing can only read: it was made without --write.",
  notWritable: "This login is outside the pairing's own subgroup, so it can't be changed from here.",
  invalid: "keefast turned this down as invalid.",
  rateLimited: "keefast asked us to wait before trying again.",
  cancelled: "The request was cancelled.",
} as const;

const authFailed = (host: string) =>
  `keefast at ${host} didn't accept this token. It may have been revoked: make a new Gateway pairing and connect again.`;
const locked = (host: string) =>
  `keefast at ${host} is locked. Someone who runs it unlocks it with \`keefast-agent unlock\`; it is read again by itself after that.`;
const unreachable = (host: string) => `Couldn't reach keefast at ${host}.`;
const timedOut = (host: string) => `keefast at ${host} took too long to answer.`;
const unreadable = (host: string) =>
  `The server at ${host} didn't answer like a keefast gateway. Check the address and that keefast-agent serve runs there.`;
const redirected = (host: string) =>
  `The server at ${host} answered with a redirect, which isn't followed. Type the address keefast-agent serve answers on.`;
const tooLarge = (host: string) =>
  `keefast at ${host} sent more than we read. Keep only your agents' items in the pairing's subgroups.`;

const fail = (code: VaultSourceErrorCode, message: string, retryAt?: string) =>
  new VaultSourceError(code, message, retryAt);

// ---- Settings ------------------------------------------------------------------------------------------------

/** `https://host[:port][/path]` without a trailing slash, query or fragment, or null. */
export function keefastBase(raw: string | undefined): URL | null {
  const value = (raw ?? "").trim();
  if (!value || value.length > 2048) return null;
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password) return null;
  return new URL(`${url.origin}${url.pathname.replace(/\/+$/, "")}`);
}

function readToken(raw: string | undefined): string | null {
  const token = (raw ?? "").trim();
  return token && token.length <= 1024 && !/\s/.test(token) ? token : null;
}

/** A host name as `VAULT_KEEFAST_PRIVATE_HOSTS` lists it: lower case, no brackets around IPv6, no trailing dot. */
const hostKey = (host: string) =>
  host
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");

interface Opened {
  base: URL;
  token: string;
  /** For the kept list: the URL and a hash of the token, never the token itself. */
  fingerprint: string;
}

function fingerprintOf(base: URL, token: string) {
  return `${base.href} ${new Bun.CryptoHasher("sha256").update(token).digest("hex")}`;
}

function openConnection(connection: VaultConnection): Opened {
  const base = keefastBase(connection.config.url);
  const token = readToken(connection.secret.token);
  if (!base || !token) throw fail("invalid_input", MESSAGES.connection);
  return { base, token, fingerprint: fingerprintOf(base, token) };
}

// ---- What keefast answers ------------------------------------------------------------------------------------

const text = (value: unknown, max = MAX_TITLE): string | undefined =>
  typeof value === "string" && value.trim() && value.length <= max ? value : undefined;

function isoDate(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const time = Date.parse(value);
  return Number.isNaN(time) ? undefined : new Date(time).toISOString();
}

/**
 * One item as keefast lists it, metadata only, or null when it isn't one. Only the fields the port knows are read, by
 * name: anything else keefast might send never reaches the engine.
 */
function itemOf(value: unknown): VaultSourceItem | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  const ref = typeof raw.ref === "string" && UUID.test(raw.ref) ? raw.ref.toLowerCase() : null;
  const title = text(raw.title);
  if (!ref || !title) return null;
  const updatedAt = isoDate(raw.updatedAt);
  if (raw.kind === "login") {
    const websites = (Array.isArray(raw.websites) ? raw.websites : []).flatMap((w) => {
      const site = w && typeof w === "object" ? (w as Record<string, unknown>) : {};
      const url = typeof site.url === "string" ? site.url : "";
      if (!url.startsWith("https://") || !vaultOrigin(url)) return [];
      const match: VaultMatch = site.match === "site" ? "site" : "exact";
      return [{ url, match }];
    });
    const username = text(raw.username);
    return {
      ref,
      kind: "login",
      title,
      ...(websites.length > 0 ? { websites } : {}),
      ...(username ? { username } : {}),
      ...(updatedAt ? { updatedAt } : {}),
    };
  }
  if (raw.kind === "key") {
    const keyName = typeof raw.keyName === "string" && KEY_NAME.test(raw.keyName) ? raw.keyName : undefined;
    return { ref, kind: "key", title, ...(keyName ? { keyName } : {}), ...(updatedAt ? { updatedAt } : {}) };
  }
  return null;
}

interface Whoami {
  vault: string;
  subgroups: string[];
  canWrite: boolean;
}

function whoamiOf(value: unknown): Whoami | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  const vault = text(raw.vault);
  if (!vault || !Array.isArray(raw.subgroups) || typeof raw.canWrite !== "boolean") return null;
  const subgroups = raw.subgroups.flatMap((s) => {
    const name = text(s);
    return name ? [name] : [];
  });
  return { vault, subgroups, canWrite: raw.canWrite };
}

// ---- HTTP ----------------------------------------------------------------------------------------------------

interface Answer {
  status: number;
  body: unknown;
  etag: string | null;
  retryAfter: string | null;
}

/** `retryAt` from a `Retry-After` header (seconds or a date), a minute from now when it says nothing usable. */
function retryAt(header: string | null, now: number): string {
  if (header && /^\d{1,7}$/.test(header.trim())) return new Date(now + Number(header.trim()) * 1000).toISOString();
  const date = header ? Date.parse(header) : Number.NaN;
  return new Date(Number.isNaN(date) || date < now ? now + DEFAULT_RETRY_MS : date).toISOString();
}

/** keefast's `code`, read only to tell its refusals apart; its message is never read. */
const codeOf = (body: unknown) =>
  body && typeof body === "object" && typeof (body as { code?: unknown }).code === "string"
    ? (body as { code: string }).code
    : null;

/** The last list a connection read, for `If-None-Match`. */
interface KeptList {
  fingerprint: string;
  etag: string;
  items: VaultSourceItem[];
}

export function createKeefastSource(options: KeefastSourceOptions = {}): VaultSource {
  const publicFetch = options.fetch ?? fetch;
  const privateFetch = options.privateFetch ?? fetch;
  const privateHosts = new Set((options.privateHosts ?? []).map(hostKey).filter(Boolean));
  const now = options.now ?? Date.now;
  const timeoutMs = options.timeoutMs ?? TIMEOUT_MS;
  const kept = new Map<string, KeptList>();

  async function send(
    opened: Pick<Opened, "base" | "token">,
    method: "GET" | "POST" | "PATCH",
    path: string,
    init: { body?: unknown; ifNoneMatch?: string; maxBytes?: number; signal?: AbortSignal | undefined } = {},
  ): Promise<Answer> {
    const { base } = opened;
    const host = base.host;
    const url = new URL(`${base.pathname.replace(/\/+$/, "")}/gateway/v1${path}`, base.origin);
    const headers: Record<string, string> = { authorization: `Bearer ${opened.token}`, accept: "application/json" };
    if (init.body !== undefined) headers["content-type"] = "application/json";
    if (init.ifNoneMatch) headers["if-none-match"] = init.ifNoneMatch;
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    const failure = () =>
      fail(
        "unreachable",
        init.signal?.aborted ? MESSAGES.cancelled : timeout.aborted ? timedOut(host) : unreachable(host),
      );
    // An operator's listed host may resolve anywhere; every other one goes through the guarded fetch.
    const listed = privateHosts.has(hostKey(base.hostname));
    let res: Response;
    try {
      res = await (listed ? privateFetch : publicFetch)(url, {
        method,
        headers,
        ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
        // A redirect could carry the token to another host: keefast's API never redirects.
        redirect: "manual",
        signal,
      });
    } catch (err) {
      if (err instanceof OutboundAddressError) throw fail("invalid_input", MESSAGES.privateHost);
      throw failure();
    }
    if (res.status >= 300 && res.status < 400 && res.status !== 304) {
      await res.body?.cancel().catch(() => {});
      throw fail("unreachable", redirected(host));
    }
    let bytes: Uint8Array | null;
    try {
      bytes = res.status === 304 ? new Uint8Array() : await readCapped(res, init.maxBytes ?? MAX_BODY_BYTES);
    } catch {
      throw failure();
    }
    if (!bytes) throw fail("unreachable", tooLarge(host));
    let body: unknown;
    if (bytes.length > 0) {
      try {
        body = JSON.parse(new TextDecoder().decode(bytes));
      } catch {
        body = undefined;
      }
    }
    return { status: res.status, body, etag: res.headers.get("etag"), retryAfter: res.headers.get("retry-after") };
  }

  /** What a refusal means. `notFound`: what a 404 means for this call (an item gone, or no gateway at all). */
  function refusalOf(host: string, answer: Answer, notFound: VaultSourceError): VaultSourceError {
    const code = codeOf(answer.body);
    switch (answer.status) {
      case 400:
        return fail("invalid_input", MESSAGES.invalid);
      case 401:
        return fail("auth_failed", authFailed(host));
      case 403:
        if (code === "not_writable") return fail("not_writable", MESSAGES.notWritable);
        if (code === "read_only") return fail("read_only", MESSAGES.readOnly);
        return fail("auth_failed", authFailed(host));
      case 404:
        return notFound;
      case 423:
        return fail("unreachable", locked(host));
      case 429:
        return fail("rate_limited", MESSAGES.rateLimited, retryAt(answer.retryAfter, now()));
      default:
        return fail("unreachable", answer.status >= 500 ? unreachable(host) : unreadable(host));
    }
  }

  /** A call that answers with one item, as `list` would show it. */
  async function itemCall(
    opened: Opened,
    method: "POST" | "PATCH",
    path: string,
    body: Record<string, unknown>,
    ok: number,
    signal?: AbortSignal,
  ): Promise<VaultSourceItem> {
    const host = opened.base.host;
    const answer = await send(opened, method, path, { body, signal });
    if (answer.status !== ok) throw refusalOf(host, answer, fail("not_found", MESSAGES.notFound));
    const item = itemOf(answer.body);
    if (item?.kind !== "login") throw fail("unreachable", unreadable(host));
    return item;
  }

  function keep(connectionId: string, list: KeptList) {
    kept.delete(connectionId);
    kept.set(connectionId, list);
    while (kept.size > MAX_KEPT_LISTS) {
      const oldest = kept.keys().next().value;
      if (oldest === undefined) break;
      kept.delete(oldest);
    }
  }

  const descriptor: VaultSourceDescriptor = {
    kind: KEEFAST_SOURCE_KIND,
    name: "keefast",
    kinds: ["login", "key"],
    steps: [
      "In keefast, make a Vault for agents, with a subgroup of its Agent group for agentes.chat. Put there the logins and keys your agents may use.",
      "On the keefast host, run `keefast-agent pairing add --gateway <name> --read <subgroup>`, adding `--write` to let agents keep and change logins in the pairing's own subgroup. It prints a token once.",
      "Paste the host's address (where keefast-agent serve answers) and that token here.",
    ],
    fields: [
      {
        id: "url",
        kind: "url",
        label: "keefast host address",
        required: true,
        placeholder: "https://keefast.example.com",
      },
      { id: "token", kind: "secret", label: "Gateway pairing token", required: true },
    ],
  };

  return {
    kind: KEEFAST_SOURCE_KIND,

    describe: () => structuredClone(descriptor),

    async connect(input, signal): Promise<VaultConnectResult> {
      const base = keefastBase(input.url);
      if (!base) throw fail("invalid_input", MESSAGES.url);
      const token = readToken(input.token);
      if (!token) throw fail("invalid_input", MESSAGES.token);
      const host = base.host;
      const answer = await send({ base, token }, "GET", "/whoami", { signal });
      if (answer.status !== 200) throw refusalOf(host, answer, fail("unreachable", unreadable(host)));
      const who = whoamiOf(answer.body);
      if (!who) throw fail("unreachable", unreadable(host));
      const label = [who.vault, who.subgroups.join(", ")].filter(Boolean).join(" · ").slice(0, MAX_LABEL);
      return {
        label,
        config: {
          url: base.href.replace(/\/+$/, ""),
          canWrite: String(who.canWrite),
          // A pairing made without --write is read-only from the start (the engine clears it on the next connect).
          ...(who.canWrite ? {} : { [VAULT_READ_ONLY_CONFIG]: "true" }),
        },
        secret: { token },
      };
    },

    async list(connection, signal) {
      const opened = openConnection(connection);
      const host = opened.base.host;
      const last = kept.get(connection.id);
      const usable = last && last.fingerprint === opened.fingerprint ? last : undefined;
      const answer = await send(opened, "GET", "/items", {
        ...(usable ? { ifNoneMatch: usable.etag } : {}),
        maxBytes: MAX_LIST_BYTES,
        signal,
      });
      if (answer.status === 304 && usable) {
        keep(connection.id, usable);
        return usable.items.map((item) => structuredClone(item));
      }
      if (answer.status !== 200) throw refusalOf(host, answer, fail("unreachable", unreadable(host)));
      const raw = answer.body && typeof answer.body === "object" ? (answer.body as { items?: unknown }).items : null;
      if (!Array.isArray(raw)) throw fail("unreachable", unreadable(host));
      const items = raw.flatMap((value) => {
        const item = itemOf(value);
        return item ? [item] : [];
      });
      if (answer.etag) keep(connection.id, { fingerprint: opened.fingerprint, etag: answer.etag, items });
      else kept.delete(connection.id);
      return items.map((item) => structuredClone(item));
    },

    async reveal(connection, ref, field: VaultSecretField, signal) {
      const opened = openConnection(connection);
      if (!UUID.test(ref)) throw fail("not_found", MESSAGES.notFound);
      const host = opened.base.host;
      const answer = await send(opened, "POST", `/items/${encodeURIComponent(ref.toLowerCase())}/resolve`, {
        body: { field },
        signal,
      });
      if (answer.status !== 200) throw refusalOf(host, answer, fail("not_found", MESSAGES.notFound));
      const value =
        answer.body && typeof answer.body === "object" ? (answer.body as { value?: unknown }).value : undefined;
      if (typeof value !== "string" || !value) throw fail("not_found", MESSAGES.notFound);
      return value;
    },

    async createLogin(connection, login: VaultNewLogin, signal) {
      const opened = openConnection(connection);
      // keefast matches every website exactly, so `match` has nothing to say there.
      const body: Record<string, unknown> = {
        title: login.title,
        password: login.password,
        ...(login.username ? { username: login.username } : {}),
        ...(login.website ? { website: login.website } : {}),
        ...(login.notes ? { notes: login.notes } : {}),
      };
      return itemCall(opened, "POST", "/logins", body, 201, signal);
    },

    async updateLogin(connection, ref, change: VaultLoginChange, signal) {
      const opened = openConnection(connection);
      if (!UUID.test(ref)) throw fail("not_found", MESSAGES.notFound);
      const body: Record<string, unknown> = {
        ...(change.username !== undefined ? { username: change.username } : {}),
        ...(change.password !== undefined ? { password: change.password } : {}),
      };
      return itemCall(opened, "PATCH", `/logins/${encodeURIComponent(ref.toLowerCase())}`, body, 200, signal);
    },
  };
}
