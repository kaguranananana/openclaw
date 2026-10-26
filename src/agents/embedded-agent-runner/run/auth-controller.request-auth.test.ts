import "../../auth-profiles/external-auth.test-support.js";
import { afterEach, expect, it, vi } from "vitest";
import { createAssistantMessageEventStream } from "../../../llm/utils/event-stream.js";
import { getProviderRequestAuth } from "../../../plugins/provider-auth-authority.js";
import * as providerRuntime from "../../../plugins/provider-runtime.js";
import { createDeferredCore } from "../../../shared/deferred.js";
import { writeConfigMachineState } from "../../../state/config-machine-state-write.js";
import { withOpenClawTestState } from "../../../test-utils/openclaw-test-state.js";
import * as authorizationOwner from "../../auth-profiles/authorization.js";
import { oauthCred } from "../../auth-profiles/credential-fixtures.test-support.js";
import { createOAuthManager } from "../../auth-profiles/oauth-manager.js";
import { mockOAuthProviderOperations } from "../../auth-profiles/oauth-native-provider.test-support.js";
import * as profileLock from "../../auth-profiles/oauth-profile-lock.js";
import { readAuthProfileStoreForTest, storeWith } from "../../auth-profiles/oauth-test-utils.js";
import { upsertAuthProfileWithLockOrThrow } from "../../auth-profiles/profiles.js";
import { writePersistedAuthProfileStoreRaw } from "../../auth-profiles/sqlite.js";
import { withAuthProfileStoreAgentDir } from "../../auth-profiles/store.js";
import {
  ensureAuthProfileStoreWithoutExternalProfilesAsync,
  getApiKeyForModelCore,
} from "../../model-auth.js";
import { registerProviderStreamForModel } from "../../provider-stream.js";
import { makeAgentAssistantMessage } from "../../test-helpers/agent-message-fixtures.js";
import { makeProviderModelFixture } from "../../test-helpers/provider-model-fixture.js";
import * as modelResolver from "../model.js";
import { createEmbeddedRunAuthController, type EmbeddedRunAuthState } from "./auth-controller.js";
import * as modelHarness from "./model-harness.js";
import * as modelSetup from "./model-setup.js";
import { prepareEmbeddedRunTransport } from "./runtime-preparation.js";

const provider = "request-auth-fixture";
const profileId = `${provider}:selected`;
afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

type RequestFixture = {
  state: Parameters<Parameters<typeof withOpenClawTestState>[1]>[0];
  credential: ReturnType<typeof oauthCred>;
  agentDir: string;
  controller: ReturnType<typeof createEmbeddedRunAuthController>;
  authState: EmbeddedRunAuthState;
  refresh: ReturnType<
    typeof vi.fn<
      (credential: ReturnType<typeof oauthCred>) => Promise<ReturnType<typeof oauthCred>>
    >
  >;
  installed(this: void): string;
};
async function withRequestFixture(
  run: (fixture: RequestFixture) => Promise<void>,
  agentId = "main",
  sharedStateOwner = false,
) {
  await withOpenClawTestState(
    { layout: "state-only", agentEnv: "main", prefix: "request-auth-" },
    async (state) => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(1_900_000_000_000);
      const credential = oauthCred({
        provider,
        access: "synthetic-access-before",
        refresh: "synthetic-refresh-before",
        expires: Date.now() + 3_600_000,
        accountId: "account-a",
      });
      const store = storeWith(profileId, credential);
      if (sharedStateOwner) {
        writeConfigMachineState("auth.sharedStore", { location: "state-db" });
      }
      await state.writeAuthProfiles(store, agentId);
      const agentDir = state.agentDir(agentId);
      const refresh = vi.fn(async () => ({
        ...credential,
        access: "synthetic-access-after",
        refresh: "synthetic-refresh-after",
        expires: Date.now() + 3_600_000,
      }));
      mockOAuthProviderOperations({ refreshCredential: refresh });
      const model = makeProviderModelFixture({
        provider,
        api: "request-auth-fixture",
        id: "chat",
        baseUrl: "https://example.test",
      });
      const authState: EmbeddedRunAuthState = {
        models: { runtime: model, effective: model },
        apiKeyInfo: null,
        lastProfileId: undefined,
        runtimeAuthState: null,
        runtimeAuthRefreshCancelled: false,
        profileIndex: 0,
        thinkLevel: "off",
      };
      let installed = "";
      const controller = createEmbeddedRunAuthController({
        config: { plugins: { enabled: false } },
        agentDir,
        workspaceDir: state.workspaceDir,
        authStore: store,
        authStorage: {
          setRuntimeApiKey: (_provider, key) => {
            installed = key;
          },
        },
        profileCandidates: [profileId],
        initialThinkLevel: "off",
        attemptedThinking: new Set(),
        fallbackConfigured: false,
        allowTransientCooldownProbe: false,
        provider,
        modelId: model.id,
        state: authState,
        log: { debug() {}, info() {}, warn() {} },
      });

      try {
        await run({
          state,
          credential,
          agentDir,
          controller,
          authState,
          refresh,
          installed: () => installed,
        });
      } finally {
        controller.stopRuntimeAuthRefreshTimer();
      }
    },
  );
}

it("initializes local OAuth in the real bounded agent-exec auth scope without borrowing shared OAuth", async () => {
  await withRequestFixture(
    async ({ state, credential, agentDir, controller, authState, installed, refresh }) => {
      const sharedId = `${provider}:shared-only`;
      writePersistedAuthProfileStoreRaw(
        storeWith(sharedId, {
          ...credential,
          access: "synthetic-ambient-access",
          refresh: "synthetic-ambient-refresh",
          accountId: "ambient-account",
        }),
      );
      await withAuthProfileStoreAgentDir(agentDir, state.stateDir, async () => {
        const scoped = await ensureAuthProfileStoreWithoutExternalProfilesAsync(agentDir);
        expect(scoped.profiles[profileId]).toEqual(credential);
        expect(scoped.profiles[sharedId]).toBeUndefined();
        await expect(
          getApiKeyForModelCore({
            model: authState.models.effective,
            cfg: { plugins: { enabled: false } },
            profileId: sharedId,
            lockedProfile: true,
            allowAuthProfileFallback: false,
            agentDir,
          }),
        ).rejects.toThrow();
        await controller.initializeAuthProfile();
        expect(installed()).toBe("synthetic-access-before");
        expect(authState.lastProfileId).toBe(profileId);
        expect(getProviderRequestAuth(authState.models.effective)).toBeUndefined();
        expect(refresh).not.toHaveBeenCalled();
      });
    },
    "exec-local",
    true,
  );
});

it.each(["exhausted", "canceled", "post-auth", "returned"] as const)(
  "disposes actual captured account authorization on %s transport startup",
  async (scenario) => {
    await withRequestFixture(async ({ state, credential, authState }) => {
      if (scenario === "exhausted") {
        await state.writeAuthProfiles({
          version: 1,
          profiles: {
            [profileId]: credential,
            [`${provider}:second`]: { ...credential, access: "synthetic-second-access" },
          },
        });
      }
      const model = authState.models.runtime;
      const harness = {
        id: "openclaw",
        label: "Startup fixture",
        supports: () => ({ supported: true as const }),
        runAttempt: vi.fn(),
      };
      // Model selection and installation precede the lifecycle under test. Keep
      // auth planning, controller creation, capture, writer facts and disposal real.
      const discovery = modelResolver.createEmptyAgentDiscoveryStores();
      vi.spyOn(modelResolver, "resolveModelAsync").mockResolvedValue({
        model,
        logicalRef: { provider, model: model.id },
        ...discovery,
      });
      vi.spyOn(modelSetup, "resolveEmbeddedRunModelSetup").mockResolvedValue({
        provider,
        modelId: model.id,
        requestedModelId: model.id,
        modelSelectionChangedByHook: false,
        requestStreamTransportOverrides: undefined,
        expectedHarnessArtifact: undefined,
        agentHarness: harness,
        pluginHarnessOwnsTransport: false,
        pinnedHarnessId: undefined,
        nativeModelOwned: false,
        observedRoutes: undefined,
        nativeSessionRuntime: undefined,
        modelConfigProvider: provider,
        model,
        ...discovery,
      });
      vi.spyOn(modelHarness, "selectEmbeddedRunHarness").mockReturnValue(harness);
      const captures: {
        handle: authorizationOwner.AuthProfileAuthorization;
        dispose: ReturnType<typeof vi.fn>;
      }[] = [];
      const capture = authorizationOwner.captureAuthProfileAuthorization;
      vi.spyOn(authorizationOwner, "captureAuthProfileAuthorization").mockImplementation(
        async (params) => {
          const handle = await capture(params);
          const dispose = vi.spyOn(handle, "dispose");
          captures.push({ handle, dispose });
          return handle;
        },
      );
      const abort = new AbortController();
      vi.spyOn(providerRuntime, "prepareProviderRuntimeAuth").mockImplementation(async () => {
        if (scenario === "exhausted") {
          throw new Error("fixture runtime-auth preparation failed");
        }
        if (scenario === "canceled") {
          abort.abort(new Error("fixture startup canceled"));
        }
        return undefined;
      });
      let runtime: Awaited<ReturnType<typeof prepareEmbeddedRunTransport>> | undefined;
      try {
        const preparing = prepareEmbeddedRunTransport({
          assertCurrent: () => {},
          runParams: {
            runId: `startup-${scenario}`,
            sessionId: "startup-session",
            sessionKey: "agent:main:startup-session",
            agentId: "main",
            prompt: "Synthetic startup",
            workspaceDir: state.workspaceDir,
            timeoutMs: 5000,
            config: { plugins: { enabled: false } },
            abortSignal: abort.signal,
            thinkLevel: "off",
          },
          provider,
          modelId: model.id,
          agentDir: state.agentDir(),
          workspaceDir: state.workspaceDir,
          globalLane: "test",
          hookRunner: undefined,
          hookContext: { sessionId: "startup-session", workspaceDir: state.workspaceDir },
          markStartupStage: (stage) => {
            if (scenario === "post-auth" && stage === "auth") {
              throw new Error("fixture post-auth preparation failed");
            }
          },
          notifyExecutionPhase: () => {},
          fallbackConfigured: false,
        });
        if (scenario === "returned") {
          runtime = await preparing;
          expect(captures).toHaveLength(1);
          expect(captures[0]!.dispose).not.toHaveBeenCalled();
          captures[0]!.handle.assertCurrent();
          expect(getProviderRequestAuth(runtime.snapshot().effectiveModel)).toBeDefined();
          runtime.stopRuntimeAuthRefreshTimer();
        } else {
          await expect(preparing).rejects.toThrow();
          expect(captures).toHaveLength(scenario === "exhausted" ? 2 : 1);
        }
        for (const { handle, dispose } of captures) {
          expect(dispose).toHaveBeenCalledOnce();
          expect(() => handle.assertCurrent()).toThrow(/disconnected or replaced/);
        }
      } finally {
        runtime?.stopRuntimeAuthRefreshTimer();
        // A red run must release its real resources after the assertions, too.
        for (const { handle } of captures) {
          handle.dispose();
        }
      }
    });
  },
);

it("renews the selected canonical OAuth owner between physical requests in one attempt", async () => {
  await withRequestFixture(
    async ({ state, credential, controller, authState, refresh, installed }) => {
      await controller.initializeAuthProfile();
      const capturedAttemptKey = installed();
      const requests: string[] = [];
      vi.spyOn(providerRuntime, "resolveProviderStreamFn").mockImplementation(
        ({ context: factory }) =>
          (_model, _context, options) => {
            const stream = createAssistantMessageEventStream();
            void (async () => {
              try {
                // The external transport consumes the optional host capability.
                const auth = await factory.requestAuth?.resolve({ signal: options?.signal });
                auth?.assertCurrent();
                requests.push(auth ? auth.apiKey : (options?.apiKey ?? ""));
                const message = makeAgentAssistantMessage({
                  content: [{ type: "text", text: "one result" }],
                  stopReason: "stop",
                });
                stream.push({ type: "done", reason: "stop", message });
              } catch (error) {
                stream.push({
                  type: "error",
                  reason: "error",
                  error: makeAgentAssistantMessage({
                    content: [],
                    stopReason: "error",
                    errorMessage: String(error),
                  }),
                });
              } finally {
                stream.end();
              }
            })();
            return stream;
          },
      );
      const stream = registerProviderStreamForModel({
        model: authState.models.effective,
        allowRuntimePluginLoad: false,
      });
      if (!stream) {
        throw new Error("Missing fixture stream");
      }
      const call = async () =>
        await (
          await stream(authState.models.effective, { messages: [] }, { apiKey: capturedAttemptKey })
        ).result();
      await call();
      await call();
      expect(refresh).not.toHaveBeenCalled();
      vi.setSystemTime(Date.now() + 3_600_001);
      expect((await call()).errorMessage).toBeUndefined();
      expect(requests).toEqual([
        "synthetic-access-before",
        "synthetic-access-before",
        "synthetic-access-after",
      ]);
      expect(refresh).toHaveBeenCalledOnce();
      expect(readAuthProfileStoreForTest(state.agentDir()).profiles[profileId]).toMatchObject({
        access: "synthetic-access-after",
        refresh: "synthetic-refresh-after",
        accountId: "account-a",
      });
      // An independent native owner publishes a refresh, preserving authorization.
      const rotation = {
        ...credential,
        access: "synthetic-canonical-rotation",
        refresh: "synthetic-canonical-refresh",
        expires: Date.now() + 3_600_000,
      };
      refresh.mockResolvedValueOnce(rotation);
      const owner = createOAuthManager();
      const current = readAuthProfileStoreForTest(state.agentDir());
      const currentCredential = current.profiles[profileId];
      if (currentCredential?.type !== "oauth") {
        throw new Error("Missing canonical credential");
      }
      await expect(
        owner.resolveOAuthAccess({
          store: current,
          credential: currentCredential,
          profileId,
          agentDir: state.agentDir(),
          forceRefresh: true,
        }),
      ).resolves.toMatchObject({ apiKey: "synthetic-canonical-rotation" });
      await call();
      expect(requests.at(-1)).toBe("synthetic-canonical-rotation");
      expect(refresh).toHaveBeenCalledTimes(2);
      await state.writeAuthProfiles(
        storeWith(profileId, {
          ...credential,
          accountId: "account-b",
          access: "wrong-account",
          expires: Date.now() + 3_600_000,
        }),
      );
      expect(await call()).toMatchObject({
        stopReason: "error",
        errorMessage: expect.stringContaining("disconnected or replaced"),
      });
      expect(requests).toHaveLength(4);
      expect(refresh).toHaveBeenCalledTimes(2);
    },
  );
});

it.each(["during-prepare", "after-resolve"] as const)(
  "refuses a reconnected canonical account %s without an automation binding",
  async (boundary) => {
    await withRequestFixture(async ({ state, credential, controller, authState }) => {
      await controller.initializeAuthProfile();
      const capability = getProviderRequestAuth(authState.models.effective);
      if (!capability) {
        throw new Error("Missing request auth");
      }
      const entered = createDeferredCore();
      const release = createDeferredCore();
      vi.spyOn(providerRuntime, "prepareProviderRuntimeAuth").mockImplementation(async () => {
        if (boundary === "during-prepare") {
          entered.resolve();
          await release.promise;
        }
        return undefined;
      });
      const pending = capability.resolve({});
      const outcome = pending.then(
        (auth) => ({ auth }),
        (error: unknown) => ({ error }),
      );
      if (boundary === "during-prepare") {
        await entered.promise;
      } else {
        await pending;
      }
      // Explicit reconnect retires authorization even when credential/account bytes match.
      await upsertAuthProfileWithLockOrThrow({ profileId, credential, agentDir: state.agentDir() });
      release.resolve();
      const result = await outcome;
      if ("auth" in result) {
        expect(() => result.auth.assertCurrent()).toThrow(/disconnected or replaced/);
      } else {
        expect(result.error).toMatchObject({ code: "MCP_AUTHORIZATION_RETIRED" });
      }
    });
  },
);

it.each(["closure", "reconnect"] as const)(
  "does not claim a new native refresh after %s while waiting on the profile lock",
  async (revocation) => {
    await withRequestFixture(async ({ state, credential, controller, authState, refresh }) => {
      await controller.initializeAuthProfile();
      vi.setSystemTime(credential.expires + 1);
      const entered = createDeferredCore();
      const release = createDeferredCore();
      const withLock = profileLock.withOAuthProfileLock;
      vi.spyOn(profileLock, "withOAuthProfileLock").mockImplementationOnce(
        async (key, operation, options) => {
          entered.resolve();
          await release.promise;
          return withLock(key, operation, options);
        },
      );
      const capability = getProviderRequestAuth(authState.models.effective);
      if (!capability) {
        throw new Error("Missing request auth");
      }
      const pending = capability.resolve({});
      const rejected = expect(pending).rejects.toThrow(
        revocation === "closure" ? /closed/ : /disconnected or replaced/,
      );
      await entered.promise;
      if (revocation === "closure") {
        controller.stopRuntimeAuthRefreshTimer();
      } else {
        await upsertAuthProfileWithLockOrThrow({
          profileId,
          credential,
          agentDir: state.agentDir(),
        });
      }
      release.resolve();
      await rejected;
      expect(refresh).not.toHaveBeenCalled();
      expect(readAuthProfileStoreForTest(state.agentDir()).profiles[profileId]).toEqual(credential);
    });
  },
);

it("settles an already claimed native refresh after request closure without returning its bearer", async () => {
  await withRequestFixture(async ({ state, credential, controller, authState, refresh }) => {
    await controller.initializeAuthProfile();
    vi.setSystemTime(credential.expires + 1);
    const entered = createDeferredCore();
    const release = createDeferredCore();
    refresh.mockImplementationOnce(async () => {
      entered.resolve();
      await release.promise;
      return {
        ...credential,
        access: "settled-access",
        refresh: "settled-refresh",
        expires: Date.now() + 3_600_000,
      };
    });
    const capability = getProviderRequestAuth(authState.models.effective);
    if (!capability) {
      throw new Error("Missing request auth");
    }
    const pending = capability.resolve({});
    const rejected = expect(pending).rejects.toThrow(/closed/);
    await entered.promise;
    controller.stopRuntimeAuthRefreshTimer();
    release.resolve();
    await rejected;
    expect(refresh).toHaveBeenCalledOnce();
    expect(readAuthProfileStoreForTest(state.agentDir()).profiles[profileId]).toMatchObject({
      access: "settled-access",
      refresh: "settled-refresh",
    });
  });
});
