import "../../auth-profiles/external-auth.test-support.js";
import { afterEach, expect, it, vi } from "vitest";
import { createAssistantMessageEventStream } from "../../../llm/utils/event-stream.js";
import * as providerRuntime from "../../../plugins/provider-runtime.js";
import { withOpenClawTestState } from "../../../test-utils/openclaw-test-state.js";
import { oauthCred } from "../../auth-profiles/credential-fixtures.test-support.js";
import { mockOAuthProviderOperations } from "../../auth-profiles/oauth-native-provider.test-support.js";
import { readAuthProfileStoreForTest, storeWith } from "../../auth-profiles/oauth-test-utils.js";
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

it("renews the selected canonical OAuth owner between physical requests in one attempt", async () => {
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
      await controller.initializeAuthProfile();
      const capturedAttemptKey = installed;
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
      try {
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
        // Another owner publishes a still-unexpired rotation during the attempt.
        await state.writeAuthProfiles(
          storeWith(profileId, {
            ...credential,
            access: "synthetic-canonical-rotation",
            refresh: "synthetic-canonical-refresh",
            expires: Date.now() + 3_600_000,
          }),
        );
        await call();
        expect(requests.at(-1)).toBe("synthetic-canonical-rotation");
        expect(refresh).toHaveBeenCalledOnce();
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
          errorMessage: expect.stringContaining("changed account identity"),
        });
        expect(requests).toHaveLength(4);
        expect(refresh).toHaveBeenCalledOnce();
      } finally {
        controller.stopRuntimeAuthRefreshTimer();
      }
    },
  );
});
