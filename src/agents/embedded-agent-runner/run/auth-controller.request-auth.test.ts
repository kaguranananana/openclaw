import "../../auth-profiles/external-auth.test-support.js";
import { afterEach, expect, it, vi } from "vitest";
import { createAssistantMessageEventStream } from "../../../llm/utils/event-stream.js";
import { getProviderRequestAuth } from "../../../plugins/provider-auth-authority.js";
import * as providerRuntime from "../../../plugins/provider-runtime.js";
import { createDeferredCore } from "../../../shared/deferred.js";
import { withOpenClawTestState } from "../../../test-utils/openclaw-test-state.js";
import { oauthCred } from "../../auth-profiles/credential-fixtures.test-support.js";
import { createOAuthManager } from "../../auth-profiles/oauth-manager.js";
import { mockOAuthProviderOperations } from "../../auth-profiles/oauth-native-provider.test-support.js";
import * as profileLock from "../../auth-profiles/oauth-profile-lock.js";
import { readAuthProfileStoreForTest, storeWith } from "../../auth-profiles/oauth-test-utils.js";
import { upsertAuthProfileWithLockOrThrow } from "../../auth-profiles/profiles.js";
import { registerProviderStreamForModel } from "../../provider-stream.js";
import { makeAgentAssistantMessage } from "../../test-helpers/agent-message-fixtures.js";
import { makeProviderModelFixture } from "../../test-helpers/provider-model-fixture.js";
import { createEmbeddedRunAuthController, type EmbeddedRunAuthState } from "./auth-controller.js";

const provider = "request-auth-fixture";
const profileId = `${provider}:selected`;
afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

type RequestFixture = {
  state: Parameters<Parameters<typeof withOpenClawTestState>[1]>[0];
  credential: ReturnType<typeof oauthCred>;
  controller: ReturnType<typeof createEmbeddedRunAuthController>;
  authState: EmbeddedRunAuthState;
  refresh: ReturnType<
    typeof vi.fn<
      (credential: ReturnType<typeof oauthCred>) => Promise<ReturnType<typeof oauthCred>>
    >
  >;
  installed(this: void): string;
};
async function withRequestFixture(run: (fixture: RequestFixture) => Promise<void>) {
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
      await state.writeAuthProfiles(store);
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
        agentDir: state.agentDir(),
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
