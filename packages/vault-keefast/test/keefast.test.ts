/**
 * keefast as a Vault source (ADR 0190), against a fake Headless host: the contract every source keeps (as
 * `packages/adapters/test/vault-sources.test.ts` runs it on the others), then what is keefast's own: each refusal's
 * code, `423` as `unreachable`, the writes' requests, `read_only` against `not_writable`, the kept list and `304`, and
 * which `fetch` a host goes through.
 */
import { describe, expect, test } from "bun:test";
import {
  createMemoryPubSub,
  noPlatformCredentials,
  OutboundAddressError,
  type VaultConnection,
  VaultSourceError,
  type VaultSourceErrorCode,
} from "@agenteschat/adapters";
import { testConfig } from "@agenteschat/config";
import type { Database } from "@agenteschat/db";
import { resolveAdapters } from "@agenteschat/modules";
import { createKeefastSource, KEEFAST_SOURCE_KIND, keefastVaultModule } from "../src";
import { createFakeKeefast, FAKE_BASE, FAKE_TOKEN, type FakeEntry } from "./fake-keefast";

const CODES: VaultSourceErrorCode[] = [
  "auth_failed",
  "locked",
  "many_vaults",
  "no_vault",
  "folder_missing",
  "not_found",
  "rate_limited",
  "unreachable",
  "unsupported",
  "invalid_input",
  "read_only",
  "not_writable",
];

const LOGIN_REF = "6f1c2d3e-0000-4000-8000-000000000001";
const KEY_REF = "6f1c2d3e-0000-4000-8000-000000000002";
const OTHER_REF = "6f1c2d3e-0000-4000-8000-000000000003";
const MISSING_REF = "6f1c2d3e-0000-4000-8000-0000000000ff";
const VALUES = ["fake-kf-login-pass-NEVER-SHOWN-1", "fake-kf-api-key-NEVER-SHOWN-2", "fake-kf-other-NEVER-SHOWN-3"];
const REFUSED_TOKEN = "kfg_refused-token-NEVER-SHOWN-9999";
const SECRETS = [FAKE_TOKEN, REFUSED_TOKEN, ...VALUES];

const entries = (): FakeEntry[] => [
  {
    ref: LOGIN_REF,
    kind: "login",
    title: "Acme admin",
    username: "ana@acme.example",
    websites: [{ url: "https://admin.acme.example/login", match: "exact" }],
    updatedAt: "2026-11-01T10:00:00Z",
    value: VALUES[0] ?? "",
    own: true,
  },
  { ref: KEY_REF, kind: "key", title: "ACME_API_KEY", keyName: "ACME_API_KEY", value: VALUES[1] ?? "" },
  {
    ref: OTHER_REF,
    kind: "login",
    title: "Shared shop",
    username: "team",
    websites: [{ url: "https://shop.acme.example", match: "exact" }],
    value: VALUES[2] ?? "",
  },
];

function setup(options: { canWrite?: boolean } = {}) {
  const fake = createFakeKeefast(entries(), options);
  const source = createKeefastSource({ fetch: fake.fetch, timeoutMs: 1_000 });
  return { fake, source };
}

const INPUT = { url: FAKE_BASE, token: FAKE_TOKEN };

async function connected(source: ReturnType<typeof createKeefastSource>, id = "conn-1"): Promise<VaultConnection> {
  const result = await source.connect(INPUT);
  return { id, orgId: "org-1", config: result.config, secret: result.secret };
}

async function failure(run: () => Promise<unknown>): Promise<VaultSourceError> {
  try {
    await run();
  } catch (err) {
    expectClean(err);
    return err as VaultSourceError;
  }
  throw new Error("expected a failure");
}

/** A failure is ours: a coded `VaultSourceError` whose every visible part carries no secret and no keefast text. */
function expectClean(err: unknown) {
  expect(err).toBeInstanceOf(VaultSourceError);
  if (!(err instanceof VaultSourceError)) return;
  expect(CODES).toContain(err.code);
  expect(err.cause).toBeUndefined();
  const visible = [err.message, String(err), JSON.stringify(err), err.stack ?? "", err.retryAt ?? ""].join("\n");
  for (const secret of SECRETS) expect(visible).not.toContain(secret);
  expect(visible).not.toContain("refused ");
  expect(visible).not.toContain("ECONNREFUSED");
}

describe("Vault source contract: keefast", () => {
  test("describes a connect card whose secret fields are secret", () => {
    const { source } = setup();
    const d = source.describe();
    expect(d.kind).toBe(KEEFAST_SOURCE_KIND);
    expect(d.name).toBe("keefast");
    expect(d.kinds).toEqual(["login", "key"]);
    expect(d.steps.length).toBe(3);
    expect(d.steps.join("\n")).toContain("keefast-agent pairing add --gateway <name> --read <subgroup>");
    expect(d.fields.map((f) => [f.id, f.kind, f.required])).toEqual([
      ["url", "url", true],
      ["token", "secret", true],
    ]);
    for (const field of d.fields) expect(field.label.length).toBeGreaterThan(0);
    d.steps.push("changed");
    expect(source.describe().steps).not.toContain("changed");
  });

  test("connect keeps what is secret in `secret` only", async () => {
    const { source } = setup();
    const result = await source.connect({ url: `${FAKE_BASE}/`, token: ` ${FAKE_TOKEN} ` });
    expect(result).toEqual({
      label: "Agents · agentes, shared",
      config: { url: FAKE_BASE, canWrite: "true" },
      secret: { token: FAKE_TOKEN },
    });
    const shown = JSON.stringify({ label: result.label, config: result.config });
    for (const secret of SECRETS) expect(shown).not.toContain(secret);
  });

  test("list is metadata only, even when the host sends more", async () => {
    const { fake, source } = setup();
    fake.state.leak = true;
    const items = await source.list(await connected(source));
    const listed = JSON.stringify(items);
    for (const secret of SECRETS) expect(listed).not.toContain(secret);
    expect(items).toEqual([
      {
        ref: LOGIN_REF,
        kind: "login",
        title: "Acme admin",
        username: "ana@acme.example",
        websites: [{ url: "https://admin.acme.example/login", match: "exact" }],
        updatedAt: "2026-11-01T10:00:00.000Z",
      },
      { ref: KEY_REF, kind: "key", title: "ACME_API_KEY", keyName: "ACME_API_KEY" },
      {
        ref: OTHER_REF,
        kind: "login",
        title: "Shared shop",
        username: "team",
        websites: [{ url: "https://shop.acme.example", match: "exact" }],
      },
    ]);
  });

  test("reveal gives exactly the one value asked for", async () => {
    const { fake, source } = setup();
    const connection = await connected(source);
    expect(await source.reveal(connection, LOGIN_REF, "password")).toBe(VALUES[0] ?? "");
    expect(await source.reveal(connection, KEY_REF, "key")).toBe(VALUES[1] ?? "");
    const resolves = fake.requests.filter((r) => r.path.endsWith("/resolve"));
    expect(resolves.map((r) => [r.method, r.path, r.body])).toEqual([
      ["POST", `/gateway/v1/items/${LOGIN_REF}/resolve`, { field: "password" }],
      ["POST", `/gateway/v1/items/${KEY_REF}/resolve`, { field: "key" }],
    ]);
  });

  test("every failure is a coded VaultSourceError that never carries a secret", async () => {
    const { fake, source } = setup();
    const connection = await connected(source);
    expect((await failure(() => source.connect({ url: FAKE_BASE, token: REFUSED_TOKEN }))).code).toBe("auth_failed");
    expect((await failure(() => source.connect({}))).code).toBe("invalid_input");
    expect((await failure(() => source.reveal(connection, MISSING_REF, "password"))).code).toBe("not_found");
    expect((await failure(() => source.reveal(connection, "../../etc/passwd", "password"))).code).toBe("not_found");
    expect((await failure(() => source.list({ ...connection, secret: {}, config: {} }))).code).toBe("invalid_input");
    fake.state.down = true;
    expect((await failure(() => source.list(connection))).code).toBe("unreachable");
    expect((await failure(() => source.connect(INPUT))).code).toBe("unreachable");
    expect((await failure(() => source.reveal(connection, LOGIN_REF, "password"))).code).toBe("unreachable");
  });
});

describe("what keefast's answers mean", () => {
  /** A source whose host answers every request with this status and keefast's `{ code, message }`. */
  function answering(status: number, code: string, headers: Record<string, string> = {}) {
    const fetch = (async () =>
      new Response(JSON.stringify({ code, message: `keefast says ${code}: ${SECRETS.join(" ")}` }), {
        status,
        headers: { "content-type": "application/json", ...headers },
      })) as unknown as typeof globalThis.fetch;
    return createKeefastSource({ fetch, now: () => Date.parse("2026-11-17T12:00:00Z"), timeoutMs: 1_000 });
  }
  const connection: VaultConnection = {
    id: "c",
    orgId: "o",
    config: { url: FAKE_BASE, canWrite: "true" },
    secret: { token: FAKE_TOKEN },
  };

  const cases: [number, string, VaultSourceErrorCode][] = [
    [400, "invalid_input", "invalid_input"],
    [401, "unauthorized", "auth_failed"],
    [403, "read_only", "read_only"],
    [403, "not_writable", "not_writable"],
    [404, "not_found", "not_found"],
    [423, "locked", "unreachable"],
    [429, "rate_limited", "rate_limited"],
    [500, "internal", "unreachable"],
    [503, "unavailable", "unreachable"],
  ];
  for (const [status, code, ours] of cases) {
    test(`${status} ${code} is ${ours}`, async () => {
      const source = answering(status, code, status === 429 ? { "retry-after": "30" } : {});
      const updated = await failure(
        () => source.updateLogin?.(connection, LOGIN_REF, { password: "fake-new" }) ?? Promise.resolve(),
      );
      expect(updated.code).toBe(ours);
      if (status === 429) expect(updated.retryAt).toBe("2026-11-17T12:00:30.000Z");
    });
  }

  test("a locked host is unreachable, retried by itself, and the message says how to unlock it", async () => {
    const { fake, source } = setup();
    const connection = await connected(source);
    fake.state.locked = true;
    for (const run of [
      () => source.list(connection),
      () => source.reveal(connection, LOGIN_REF, "password"),
      () => source.connect(INPUT),
    ]) {
      const err = await failure(run);
      expect(err.code).toBe("unreachable");
      expect(err.message).toBe(
        "keefast at keefast.acme.example is locked. Someone who runs it unlocks it with `keefast-agent unlock`; it is read again by itself after that.",
      );
    }
    fake.state.locked = false;
    expect(await source.reveal(connection, LOGIN_REF, "password")).toBe(VALUES[0] ?? "");
  });

  test("a 404 on whoami or the list is no gateway there, not a missing item", async () => {
    const source = answering(404, "not_found");
    expect((await failure(() => source.connect(INPUT))).code).toBe("unreachable");
    expect((await failure(() => source.list(connection))).code).toBe("unreachable");
  });

  test("a redirect is never followed", async () => {
    const fetch = (async () =>
      new Response(null, {
        status: 302,
        headers: { location: "https://elsewhere.example/" },
      })) as unknown as typeof globalThis.fetch;
    const err = await failure(() => createKeefastSource({ fetch }).connect(INPUT));
    expect(err.code).toBe("unreachable");
    expect(err.message).toContain("redirect");
  });

  test("an answer that isn't keefast's is unreachable", async () => {
    const fetch = (async () =>
      new Response("<html>hello</html>", { status: 200 })) as unknown as typeof globalThis.fetch;
    const source = createKeefastSource({ fetch });
    expect((await failure(() => source.connect(INPUT))).code).toBe("unreachable");
    expect((await failure(() => source.list(connection))).code).toBe("unreachable");
    expect((await failure(() => source.reveal(connection, LOGIN_REF, "password"))).code).toBe("not_found");
  });

  test("the engine's signal stops a call; the deadline does too", async () => {
    const { fake, source } = setup();
    const connection = await connected(source);
    const stopped = AbortSignal.abort();
    const err = await failure(() => source.list(connection, stopped));
    expect(err).toMatchObject({ code: "unreachable", message: "The request was cancelled." });
    expect(fake.requests.at(-1)?.signal?.aborted).toBe(true);

    const hanging = ((_: unknown, init: RequestInit = {}) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      })) as unknown as typeof fetch;
    const slow = createKeefastSource({ fetch: hanging, timeoutMs: 20 });
    expect(await failure(() => slow.connect(INPUT))).toMatchObject({
      code: "unreachable",
      message: "keefast at keefast.acme.example took too long to answer.",
    });
  });
});

describe("writes", () => {
  test("createLogin and updateLogin send the Gateway API's shapes, with the token only in its header", async () => {
    const { fake, source } = setup();
    const connection = await connected(source);
    const created = await source.createLogin?.(connection, {
      title: "shop.acme.example",
      username: "agent@acme.example",
      password: "fake-made-NEVER-SHOWN-7",
      website: "https://shop.acme.example",
      match: "site",
      notes: "made by an agent",
    });
    expect(created).toMatchObject({
      kind: "login",
      title: "shop.acme.example",
      username: "agent@acme.example",
      websites: [{ url: "https://shop.acme.example", match: "exact" }],
    });
    expect(JSON.stringify(created)).not.toContain("fake-made-NEVER-SHOWN-7");
    const ref = created?.ref ?? "";
    const updated = await source.updateLogin?.(connection, ref, { password: "fake-changed-NEVER-SHOWN-8" });
    expect(updated?.ref).toBe(ref);
    expect(await source.reveal(connection, ref, "password")).toBe("fake-changed-NEVER-SHOWN-8");

    const writes = fake.requests.filter((r) => r.method !== "GET" && !r.path.endsWith("/resolve"));
    expect(writes.map((r) => [r.method, r.path, r.body])).toEqual([
      [
        "POST",
        "/gateway/v1/logins",
        {
          title: "shop.acme.example",
          password: "fake-made-NEVER-SHOWN-7",
          username: "agent@acme.example",
          website: "https://shop.acme.example",
          notes: "made by an agent",
        },
      ],
      ["PATCH", `/gateway/v1/logins/${ref}`, { password: "fake-changed-NEVER-SHOWN-8" }],
    ]);
    for (const request of fake.requests) {
      expect(request.headers.authorization).toBe(`Bearer ${FAKE_TOKEN}`);
      expect(request.path).not.toContain(FAKE_TOKEN);
      expect(request.redirect).toBe("manual");
    }
    expect(writes.every((r) => r.headers["content-type"] === "application/json")).toBe(true);
  });

  test("a pairing without --write is read_only from connect on; a login outside its subgroup is not_writable", async () => {
    const readOnly = setup({ canWrite: false });
    const result = await readOnly.source.connect(INPUT);
    expect(result.config).toEqual({ url: FAKE_BASE, canWrite: "false", readOnly: "true" });
    const ro = await connected(readOnly.source);
    const login = { title: "x", password: "fake-ro-NEVER-SHOWN" };
    expect((await failure(() => readOnly.source.createLogin?.(ro, login) ?? Promise.resolve())).code).toBe("read_only");
    expect(
      (await failure(() => readOnly.source.updateLogin?.(ro, LOGIN_REF, { password: "p" }) ?? Promise.resolve())).code,
    ).toBe("read_only");

    const { fake, source } = setup();
    const connection = await connected(source);
    const err = await failure(
      () => source.updateLogin?.(connection, OTHER_REF, { password: "fake-x-NEVER-SHOWN" }) ?? Promise.resolve(),
    );
    expect(err.code).toBe("not_writable");
    expect(fake.state.entries.find((e) => e.ref === OTHER_REF)?.value).toBe(VALUES[2] ?? "");
    // The same pairing still changes a login in its own subgroup.
    await source.updateLogin?.(connection, LOGIN_REF, { username: "ops@acme.example" });
    expect(fake.state.entries.find((e) => e.ref === LOGIN_REF)?.username).toBe("ops@acme.example");
    expect(
      (await failure(() => source.updateLogin?.(connection, MISSING_REF, { password: "p" }) ?? Promise.resolve())).code,
    ).toBe("not_found");
  });
});

describe("the kept list", () => {
  test("a list again sends the last ETag and, on 304, gives the same items without keefast reading them", async () => {
    const { fake, source } = setup();
    const connection = await connected(source);
    const first = await source.list(connection);
    const second = await source.list(connection);
    expect(second).toEqual(first);
    const lists = fake.requests.filter((r) => r.path === "/gateway/v1/items");
    expect(lists.map((r) => r.headers["if-none-match"])).toEqual([undefined, '"rev-1"']);

    // A change in keefast moves the ETag: the new list comes whole.
    await source.createLogin?.(connection, { title: "new", password: "fake-new-NEVER-SHOWN" });
    expect(await source.list(connection)).toHaveLength(4);

    // A copy each time: changing what came back changes nothing kept.
    const third = await source.list(connection);
    third.pop();
    expect(await source.list(connection)).toHaveLength(4);
  });

  test("another token or connection never reuses a kept list", async () => {
    const { fake, source } = setup();
    const connection = await connected(source);
    await source.list(connection);
    await source.list({ ...connection, id: "conn-2" });
    await failure(() => source.list({ ...connection, secret: { token: REFUSED_TOKEN } }));
    const lists = fake.requests.filter((r) => r.path === "/gateway/v1/items");
    expect(lists.map((r) => r.headers["if-none-match"])).toEqual([undefined, undefined, undefined]);
  });
});

describe("which fetch a host goes through", () => {
  function routed(privateHosts: string[]) {
    const fake = createFakeKeefast(entries());
    const seen: string[] = [];
    const via =
      (name: string, inner: typeof fetch) =>
      (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
        seen.push(name);
        const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
        // The fake answers on its own origin; the host under test is what the source chose by.
        return inner(new URL(`${url.pathname}${url.search}`, FAKE_BASE), init);
      };
    const source = createKeefastSource({
      fetch: via("public", fake.fetch) as typeof fetch,
      privateFetch: via("private", fake.fetch) as typeof fetch,
      privateHosts,
    });
    return { source, seen, fake };
  }

  test("a host the operator listed goes through plain fetch, with a redirect never followed", async () => {
    const { source, seen, fake } = routed(["keefast.lan", "100.64.0.7"]);
    await source.connect({ url: "https://KEEFAST.lan./", token: FAKE_TOKEN });
    await source.connect({ url: "https://100.64.0.7:8443", token: FAKE_TOKEN });
    await source.connect({ url: "https://keefast.acme.example", token: FAKE_TOKEN });
    expect(seen).toEqual(["private", "private", "public"]);
    expect(fake.requests.every((r) => r.redirect === "manual")).toBe(true);
  });

  test("listed or not, the address must be https and carry no user or password", async () => {
    const { source, seen } = routed(["keefast.lan"]);
    for (const url of ["http://keefast.lan", "https://ana:pw@keefast.lan", "ftp://keefast.lan", ""]) {
      expect((await failure(() => source.connect({ url, token: FAKE_TOKEN }))).code).toBe("invalid_input");
    }
    expect(seen).toEqual([]);
  });

  test("a private address the guarded fetch refuses is invalid_input, and says how to allow it", async () => {
    const refusing = (async () => {
      throw new OutboundAddressError();
    }) as unknown as typeof fetch;
    const source = createKeefastSource({ fetch: refusing, privateHosts: ["keefast.lan"] });
    const err = await failure(() => source.connect({ url: "https://keefast.internal.example", token: FAKE_TOKEN }));
    expect(err.code).toBe("invalid_input");
    expect(err.message).toContain("VAULT_KEEFAST_PRIVATE_HOSTS");
  });

  test("the module reads the list from the server's config and adds the keefast source", async () => {
    const fake = createFakeKeefast(entries());
    const privateCalls: string[] = [];
    const module = keefastVaultModule({
      fetch: (async () => {
        throw new OutboundAddressError();
      }) as unknown as typeof fetch,
      privateFetch: (async (input: string | URL | Request, init?: RequestInit) => {
        privateCalls.push(String(input));
        const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
        return fake.fetch(new URL(url.pathname, FAKE_BASE), init);
      }) as unknown as typeof fetch,
    });
    const config = testConfig({ VAULT_KEEFAST_PRIVATE_HOSTS: " Keefast.LAN , localhost " });
    expect(config.VAULT_KEEFAST_PRIVATE_HOSTS).toEqual(["keefast.lan", "localhost"]);
    const defaults = {
      pubsub: createMemoryPubSub(),
      platformCredentials: noPlatformCredentials,
      vaultSources: {},
    } as unknown as Parameters<typeof resolveAdapters>[2];
    const { adapters, overridden } = await resolveAdapters(
      [module],
      { config, db: {} as Database, edition: "selfhost", version: "test" },
      defaults,
      {},
    );
    expect(overridden).toEqual(["vault-keefast:vaultSources.keefast"]);
    const source = adapters.vaultSources?.keefast;
    if (!source) throw new Error("no keefast source");
    expect((await source.connect({ url: "https://keefast.lan", token: FAKE_TOKEN })).label).toBe(
      "Agents · agentes, shared",
    );
    expect(privateCalls).toEqual(["https://keefast.lan/gateway/v1/whoami"]);
    expect((await failure(() => source.connect({ url: "https://other.lan", token: FAKE_TOKEN }))).code).toBe(
      "invalid_input",
    );
  });
});
