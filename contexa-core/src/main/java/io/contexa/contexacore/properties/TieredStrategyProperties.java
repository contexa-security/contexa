/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.properties;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.std.llm.client.AnthropicEffort;
import io.contexa.contexacore.std.llm.client.AnthropicThinkingMode;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "contexa.security.tiered")
public class TieredStrategyProperties {

    private Layer1 layer1 = new Layer1();
    private Layer2 layer2 = new Layer2();

    private Truncation truncation = new Truncation();
    private Security security = new Security();
    private PromptRuntime promptRuntime = new PromptRuntime();
    private Determinism determinism = new Determinism();
    private PromptBundle promptBundle = new PromptBundle();
    private ArgumentOrigin argumentOrigin = new ArgumentOrigin();

    /**
     * CQ-1 (argument origin): what the event carries of the argument origins a host gives a protected method
     * ({@code ArgumentOrigins}), so what the decision prompt may state of them (contexa.security.tiered.argument-origin.*).
     * The settings are applied when the event is built, so the sealed context holds exactly what the prompt states.
     */
    @Data
    public static class ArgumentOrigin {

        /**
         * Whether the sentence of the tool output a value first appeared in is carried and quoted. Off, the decision
         * states only where the value first appeared (the tool), not the sentence: the sentence is the tool's output
         * and may hold sensitive text.
         */
        private boolean quoteExcerpt = true;

        /** The longest quoted sentence in characters, 0 to 300; 0 quotes none. */
        private int maxExcerptChars = 300;
    }

    /**
     * Which prompt bundle the security decision runs (W3-16, version management function 4): by default the bundle this
     * configuration names, or the registry's state, scope and canary share. A bundle the build cannot run falls back to
     * the build's default bundle.
     */
    @Data
    public static class PromptBundle {

        public enum Selector {
            CONFIGURATION,
            REGISTRY
        }

        /** The bundle version the configuration selector runs; blank for the build's default bundle. */
        private String active;

        /** Which selector chooses the bundle: this configuration, or the prompt governance registry. */
        private Selector selector = Selector.CONFIGURATION;

        /** W6-9: the shadow run of the registry's shadow release. */
        private Shadow shadow = new Shadow();

        @Data
        public static class Shadow {

            /** The share of requests a shadow release runs on, 0 to 100; 0 runs none. */
            private int samplePercent = 0;

            /** The shadow runs allowed per UTC day, one model call each. */
            private int dailyCallCap = 100;
        }
    }

    @Data
    public static class Security {

        private List<String> trustedProxies = Collections.emptyList();

        private boolean trustedProxyValidationEnabled = true;
    }

    /**
     * W4-6: the determinism settings a security decision asks every provider for (contexa.security.tiered.determinism.*).
     * The options factory sets the ones the provider and model take and records the others on the call.
     */
    @Data
    public static class Determinism {
        private Double temperature = 0.0d;
        private Integer seed = 1;
    }

    @Data
    public static class PromptRuntime {
        public enum BudgetEnforcement {
            OBSERVE_ONLY,
            ENFORCE
        }

        /**
         * When disabled, runtime falls back to validated converter mode but never re-enables raw semantic fallback.
         */
        private boolean nativeStructuredOutputEnabled = true;
        private List<String> nativeStructuredOutputDisabledProfiles = Collections.emptyList();
        /**
         * Prompt runtime telemetry remains on by default for official verification and rollout diagnostics.
         */
        private boolean telemetryEnabled = true;
        private BudgetEnforcement budgetEnforcement = BudgetEnforcement.OBSERVE_ONLY;

        public boolean isNativeStructuredOutputEnabledForProfile(String profileKey) {
            if (!nativeStructuredOutputEnabled) {
                return false;
            }
            if (profileKey == null || profileKey.isBlank()) {
                return true;
            }
            return nativeStructuredOutputDisabledProfiles == null
                    || nativeStructuredOutputDisabledProfiles.stream()
                    .filter(value -> value != null && !value.isBlank())
                    .noneMatch(value -> value.trim().equalsIgnoreCase(profileKey.trim()));
        }
    }

    @Data
    public static class Truncation {
        private Layer1Truncation layer1 = new Layer1Truncation();
        private Layer2Truncation layer2 = new Layer2Truncation();

        @Data
        public static class Layer1Truncation {
            private int userAgent = 150;
            private int payload = 200;
            private int ragDocument = 180;
        }

        @Data
        public static class Layer2Truncation {
            private int userAgent = 150;
            private int payload = 1000;
            private int ragDocument = 500;
        }

    }

    private VectorCache vectorCache = new VectorCache();

    @Data
    public static class VectorCache {
        private int maxSize = 10000;
        private int expireMinutes = 5;
        private boolean enabled = true;
        private boolean recordStats = true;
        /** Clear the cached searches a write can change: the writer's, its organisation's and unscoped ones (W2-15). */
        private boolean invalidateOnWrite = true;
    }

    @Data
    public static class Layer1 {
        private Rag rag = new Rag();
        private Session session = new Session();
        private Cache cache = new Cache();
        private Timeout timeout = new Timeout();
        private Prompt prompt = new Prompt();
        private int vectorSearchLimit = 12;
        private String defaultBudgetProfile = "CORTEX_L1_INTERACTIVE_STRICT";
        /**
         * W4-6 (G-5): a reasoning model's reasoning tokens count against this limit. QF-3: 2,048 cut a third of the
         * answers of claude-haiku-5-5 (a cut answer has no reason, risk or confidence), so the default is 4,096.
         */
        private int maxOutputTokens = 4096;
        private String openAiReasoningEffort = "low";
        private String openAiVerbosity = "low";
        /**
         * The thinking this layer asks of an Anthropic model: PROVIDER_DEFAULT sends no thinking field (the Spring AI
         * default options or the model's own default apply; the request is as it was before the setting existed); OFF
         * sends the model's way of turning thinking off; BUDGET sends thinking with anthropic-thinking-budget-tokens;
         * ADAPTIVE needs Spring AI 2.0.x. What each model takes follows the Claude API thinking documentation
         * (https://platform.claude.com/docs/en/build-with-claude/thinking-troubleshooting) as the capability table
         * contexa.llm.model-capabilities.anthropic.thinking states it; the start refuses a value the layer model
         * refuses. Turning thinking off changes the decisions a model makes.
         */
        private AnthropicThinkingMode anthropicThinking = AnthropicThinkingMode.PROVIDER_DEFAULT;
        /**
         * The Anthropic output_config.effort of this layer; empty sends none (the model's default). Spring AI 1.1
         * cannot send an effort, so the start refuses any value until Contexa runs on Spring AI 2.0.x.
         */
        private AnthropicEffort anthropicEffort;
        /**
         * The thinking budget (budget_tokens) of anthropic-thinking BUDGET: at least 1,024; max_tokens is then
         * max-output-tokens plus this budget. The budget is a target the model may exceed, not a cap.
         */
        private Integer anthropicThinkingBudgetTokens;
        /**
         * The tokens max_tokens adds to max-output-tokens when the model thinks without a budget (its default thinking
         * on, or adaptive thinking). 0 adds none: the thinking then shares max-output-tokens with the answer, and the
         * longer the input, the more answers are cut. A cut answer's retry adds the same allowance, not twice it.
         */
        private int anthropicThinkingAllowanceTokens = 0;

        @Data
        public static class Prompt {

            private int maxSimilarEvents = 2;

            private int maxRagDocuments = 12;

            private boolean includeEventId = false;

            private boolean includeRawTimestamp = false;

            private boolean includeRawSessionId = false;

            private boolean includeFullUserAgent = false;
        }

        @Data
        public static class Timeout {

            private long totalMs = 120000;

            private long llmMs = 90000;

            private long ragMs = 8000;

            /**
             * How long an interactive request waits for its past record search where the records are first needed. The
             * search starts at the analysis entry, so the stages before that point count towards it (W3-4). 600 ms covers
             * nearly every search: on the showcase engine the 99th percentile took 524 ms (P3-EXTRA-4).
             */
            private long interactiveRagWaitMs = 600;

            private boolean backgroundRagWarmupOnInteractiveTimeout = true;
        }

        @Data
        public static class Rag {

            private double similarityThreshold = 0.5;
        
            /**
             * Layer1 is the interactive hot path. Keep one user-scoped vector lookup by default;
             * broader/baseline/supporting lookups can be enabled for diagnostics or offline analysis.
             */
            private boolean multiQuerySearchEnabled = false;

            private boolean supportingSearchEnabled = false;
        }

        @Data
        public static class Session {

            private int maxRecentActions = 100;
        }

        @Data
        public static class Cache {

            private int maxSize = 1000;

            private int ttlMinutes = 30;
        }
    }

    @Data
    public static class Layer2 {
        private Rag rag = new Rag();
        private Cache cache = new Cache();

        private long timeoutMs = 30000;
        private boolean enableSoar = false;
        private boolean allowEscalateFinalAction = false;
        private ZeroTrustAction escalateFallbackAction = ZeroTrustAction.CHALLENGE;
        private int ragTopK = 5;
        private String defaultBudgetProfile = "CORTEX_L2_EXPERT_STRICT";
        /** W4-6 (G-5): a reasoning model's reasoning tokens count against this limit. */
        private int maxOutputTokens = 2560;
        private String openAiReasoningEffort = "low";
        private String openAiVerbosity = "low";
        /**
         * The thinking this layer asks of an Anthropic model: PROVIDER_DEFAULT sends no thinking field (the Spring AI
         * default options or the model's own default apply; the request is as it was before the setting existed); OFF
         * sends the model's way of turning thinking off; BUDGET sends thinking with anthropic-thinking-budget-tokens;
         * ADAPTIVE needs Spring AI 2.0.x. What each model takes follows the Claude API thinking documentation
         * (https://platform.claude.com/docs/en/build-with-claude/thinking-troubleshooting) as the capability table
         * contexa.llm.model-capabilities.anthropic.thinking states it; the start refuses a value the layer model
         * refuses. Turning thinking off changes the decisions a model makes.
         */
        private AnthropicThinkingMode anthropicThinking = AnthropicThinkingMode.PROVIDER_DEFAULT;
        /**
         * The Anthropic output_config.effort of this layer; empty sends none (the model's default). Spring AI 1.1
         * cannot send an effort, so the start refuses any value until Contexa runs on Spring AI 2.0.x.
         */
        private AnthropicEffort anthropicEffort;
        /**
         * The thinking budget (budget_tokens) of anthropic-thinking BUDGET: at least 1,024; max_tokens is then
         * max-output-tokens plus this budget. The budget is a target the model may exceed, not a cap.
         */
        private Integer anthropicThinkingBudgetTokens;
        /**
         * The tokens max_tokens adds to max-output-tokens when the model thinks without a budget (its default thinking
         * on, or adaptive thinking). 0 adds none: the thinking then shares max-output-tokens with the answer, and the
         * longer the input, the more answers are cut. A cut answer's retry adds the same allowance, not twice it.
         */
        private int anthropicThinkingAllowanceTokens = 0;

        @Data
        public static class Cache {

            private int maxSize = 1000;

            private int ttlMinutes = 30;
        }

        @Data
        public static class Rag {

            private double similarityThreshold = 0.5;
        }
    }

}
