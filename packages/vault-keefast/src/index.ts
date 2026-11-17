/**
 * keefast as a Vault source, through a module (ADR 0190): `keefastVaultModule()` adds the `keefast` source to the
 * Vault's sources (ADR 0144 §3) through `AgentesModule.adapters()`, merged by kind. The self-hosted server starts with
 * it (`apps/server/src/main.ts`).
 */
import { publicHttpsFetch } from "@agenteschat/engine";
import type { AgentesModule } from "@agenteschat/modules";
import { createKeefastSource, KEEFAST_SOURCE_KIND } from "./source";

export { createKeefastSource, KEEFAST_SOURCE_KIND, type KeefastSourceOptions, keefastBase } from "./source";

export interface KeefastVaultModuleOptions {
  /** The guarded `fetch` for hosts people type; `publicHttpsFetch()` by default (tests pass a fake). */
  fetch?: typeof fetch;
  /** The `fetch` for hosts the operator listed; plain `fetch` by default (tests pass a fake). */
  privateFetch?: typeof fetch;
}

export function keefastVaultModule(options: KeefastVaultModuleOptions = {}): AgentesModule {
  return {
    name: "vault-keefast",
    adapters: ({ config }) => ({
      vaultSources: {
        [KEEFAST_SOURCE_KIND]: createKeefastSource({
          fetch: options.fetch ?? publicHttpsFetch(),
          ...(options.privateFetch ? { privateFetch: options.privateFetch } : {}),
          // Only the server's operator sets this list; nothing a workspace's members type widens it.
          privateHosts: config.VAULT_KEEFAST_PRIVATE_HOSTS ?? [],
        }),
      },
    }),
  };
}
