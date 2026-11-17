# 0190. keefast as a Vault source, through a module

- Status: Accepted
- Date: 2026-11-17
- Amends: ADR 0144 (§3 sources: a fourth, added by a module, and an operator's list of private hosts; §9 sources may
  write: a write refused for one item, `not_writable`, apart from a read-only credential)
- Builds on: ADR 0002 (modules and adapters), ADR 0004 (one env var schema), ADR 0007 (sealed credentials)
- Code: the module `packages/vault-keefast` (`@agenteschat/vault-keefast`: `createKeefastSource`,
  `keefastVaultModule`; tests against a fake host in `test/`), wired in `apps/server/src/main.ts`; the code
  `not_writable` in `packages/adapters/src/vault/source.ts` (`VaultSourceErrorCode`) and
  `packages/engine/src/vault/refusals.ts` (`refuse.notWritable`), handled in `packages/engine/src/vault/agents.ts`
  (`sourceWrite`, `saveMadePassword`); `VAULT_KEEFAST_PRIVATE_HOSTS` in `packages/config/src/schema.ts`

## Context

keefast is a KeePass password manager. Its Headless host (`keefast-agent serve`) offers a **Gateway pairing**: a token
a person makes on the host (`keefast-agent pairing add --gateway <name> --read <subgroup>... [--write]`) that reads
some subgroups of the Vault's Agent group, lists their Entries as logins and keys already mapped to our items (a ref
that is the Entry's UUID, a title, a username and HTTPS websites matched exactly, or a key's name), resolves one value
at a time without a prompt, and, with `--write`, keeps new logins in the pairing's own subgroup and changes the
username or password of the logins there. It answers under `/gateway/v1/`, JSON with a bearer token:

- `GET /whoami` → `{ vault, pairing, subgroups, canWrite }`
- `GET /items` → `{ items }` with an `ETag`; `If-None-Match` answers `304` while the Vault is unchanged
- `POST /items/{ref}/resolve` `{ field, for? }` → `{ value }`
- `POST /logins` `{ title, username?, password, website?, notes?, for? }` → `201` and the item
- `PATCH /logins/{ref}` `{ username?, password?, for? }` → the item
- refusals `{ code, message }`: 400 `invalid_input`, 401 `unauthorized`, 403 `read_only` (the pairing may not write),
  403 `not_writable` (an Entry outside its own subgroup), 404 `not_found`, 423 `locked` (the host waits for
  `keefast-agent unlock`)

People whose secrets live in KeePass want their agents to use them without a copy here. The Vault already has the
port for it (ADR 0144 §3); three things don't fit as they are: where the source lives, two of keefast's refusals, and
the address keefast usually has.

## Decision

1. **A module, not a core adapter.** The source is its own workspace package, `@agenteschat/vault-keefast`
   (AGPL-3.0-only), whose `keefastVaultModule()` returns it from `AgentesModule.adapters()` as `vaultSources.keefast`,
   merged by kind like any module's (ADR 0144 §3). The self-hosted server starts with that module
   (`startServer({ edition: "selfhost", modules: [keefastVaultModule()] })` in `apps/server/src/main.ts`). Nothing in
   the engine knows keefast: access, history, the box to the computer and the runner's checks are the same for its
   items as for every other source's.

2. **A thin client.** keefast maps Entries itself, so the source checks the token with `whoami` (the connection is
   labelled `<vault> · <subgroups>`; it keeps `{ url, canWrite }` as config and the token as its secret, sealed), and
   `list`, `reveal`, `createLogin` and `updateLogin` are one request each. It reads only the item fields the port
   knows, by name, so anything else a host sends never reaches the engine. A pairing made without `--write` is
   connected read-only from the start (`config.readOnly`, ADR 0144 §9), instead of being found at the first write.
   The `for` each request may carry is left out: the port gives a source no run, and keefast logs it only as an
   unverified claim. Every call has the 60 s deadline of every source and stops with the engine's signal.

3. **The ETag is used.** A sync needs the whole list (an item not in it is marked missing), so the source keeps the
   last list it read per connection, in this process's memory (metadata only, 500 connections at most, keyed by the
   URL and a hash of the token), sends its ETag as `If-None-Match` and, on `304`, hands the engine that list again.
   keefast reads nothing while its Vault is unchanged; the engine sees no difference.

4. **`locked` is `unreachable` here.** Our `locked` means a wrong master password: the connection stops syncing until
   a person reconnects it (`WAITS_FOR_PERSON` in `packages/engine/src/vault/sync.ts`). keefast's 423 means the host
   is waiting for its operator's `keefast-agent unlock`, after which the same token works again; nothing in the
   connection is wrong. So it is `unreachable`, which the sync tries again every 10 minutes, with our own words:
   "keefast at `<host>` is locked. Someone who runs it unlocks it with `keefast-agent unlock`; it is read again by
   itself after that." The other refusals map as their names say: `unauthorized` → `auth_failed`, `read_only` →
   `read_only`, `not_writable` → `not_writable`, `not_found` → `not_found` (on `whoami` or the list, a 404 is no
   gateway there: `unreachable`), `invalid_input` → `invalid_input`, 429 → `rate_limited`, a network failure, a 5xx,
   a redirect or an answer that isn't keefast's → `unreachable`. keefast's own message is never read: our words only,
   never the token or a value (the shared contract, ADR 0144 §3).

5. **A new code, `not_writable`.** `read_only` says the credential may only read, and the engine remembers it on the
   whole connection (§9). keefast can refuse one login (outside the pairing's own subgroup) while the same pairing
   still keeps and changes others, so that refusal is its own code in the port (`VaultSourceErrorCode`) and in the
   agent's refusals (`VaultRefusalCode`, `refuse.notWritable`). A `not_writable` write is refused to the agent in
   words that name the place and the way out, and the connection is left as it was. When a made password replaces a
   login there (`saveMadePassword`) and the person didn't name the place, it is handled like a source that never
   changes a login: the new password is kept in the Vault as a new login and the answer says the login in the
   password manager keeps its old password because it can't be changed from here. When the person named the place,
   the refusal stands. The apps need no words for it: like `read_only`, it only reaches an agent's tool answer, never
   a connection's status or the connect form.

6. **Private hosts are the operator's list.** A keefast host usually sits on the same machine or tailnet as this
   server, which the guarded fetch for addresses people type (`publicHttpsFetch`: public addresses only, ADR 0144 §3)
   refuses. `VAULT_KEEFAST_PRIVATE_HOSTS` (comma-separated host names, set by whoever runs the server) lists the hosts
   that may resolve to loopback, private or tailnet addresses: a URL whose host is on it is fetched with plain
   `fetch`, still HTTPS only, no user or password in it, and a redirect never followed (`redirect: "manual"`, a 3xx
   is `unreachable`). Every other host goes through `publicHttpsFetch`, and an address it refuses is `invalid_input`
   with words that name the variable. A workspace's members can't widen the list: a name typed in the connect form
   is checked against it, never added to it.

## Consequences

- The core diff is small: one code in the port and the engine, one env var, one line in `main.ts`; the rest lives in
  the module, so a fork that carries it rebases on upstream easily.
- A host on the list is trusted by name. Whoever controls its DNS answer controls where the token goes, as with any
  host the operator names; it should be a name only the operator's network resolves.
- A locked host shows as unreachable in Settings, Vault, Connections, with the unlock in the words, and the items
  already indexed stay until it is read again.
- The kept list costs memory per connection and is lost at restart, which only means one full list.
- Left out: the `for` claim (needs run context in the port), keys or contacts written to keefast, deleting anything,
  telling a host apart from the tailnet's other names.
