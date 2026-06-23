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
package io.contexa.autoconfigure.core.hcad;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.hcad.store.BaselineDataStore;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeoutException;

@Configuration
@ConditionalOnProperty(prefix = "contexa.hcad.extreme-test", name = "enabled", havingValue = "true")
@AutoConfigureAfter(CoreLLMTieredAutoConfiguration.class)
@AutoConfigureBefore(name = "io.contexa.autoconfigure.core.std.CoreStdComponentsAutoConfiguration")
public class HcadExtremeTestAutoConfiguration {

    public static final String RUN_ID_HEADER = "X-Contexa-Test-Run-Id";
    public static final String LLM_RESULT_HEADER = "X-Contexa-Test-Llm-Result";

    @Bean(name = "hcadExtremeToolCapableLlmClient")
    @Primary
    public ToolCapableLLMClient hcadExtremeToolCapableLlmClient(ObjectMapper objectMapper) {
        return new HcadExtremeDeterministicLlmClient(objectMapper);
    }

    @Bean
    public static BeanFactoryPostProcessor hcadExtremeLlmPrimaryPostProcessor() {
        return beanFactory -> demoteProductionLlmPrimary(beanFactory, "unifiedLLMOrchestrator");
    }

    @Bean
    public HcadExtremeTestService hcadExtremeTestService() {
        return new HcadExtremeTestService();
    }

    public static class HcadExtremeDeterministicLlmClient implements ToolCapableLLMClient {

        private final ObjectMapper objectMapper;

        public HcadExtremeDeterministicLlmClient(ObjectMapper objectMapper) {
            this.objectMapper = objectMapper == null ? new ObjectMapper() : objectMapper;
        }

        @Override
        public Mono<String> call(Prompt prompt) {
            DeterministicOutcome outcome = resolveOutcome(prompt);
            return switch (outcome.kind()) {
                case ALLOW, CHALLENGE, BLOCK -> Mono.just(response(outcome));
                case PARSER_FAILURE -> Mono.just("{\"action\":\"ALLOW\",\"riskScore\":");
                case MODEL_UNAVAILABLE -> Mono.error(new IllegalStateException("HCAD extreme test model unavailable"));
                case TIMEOUT -> Mono.error(new TimeoutException("HCAD extreme test timeout"));
            };
        }

        @Override
        public <T> Mono<T> entity(Prompt prompt, Class<T> targetType) {
            return call(prompt).map(raw -> {
                try {
                    return objectMapper.readValue(raw, targetType);
                } catch (Exception ex) {
                    throw new IllegalStateException("HCAD extreme deterministic entity conversion failed", ex);
                }
            });
        }

        @Override
        public Flux<String> stream(Prompt prompt) {
            return call(prompt).flux();
        }

        @Override
        public Mono<String> callTools(Prompt prompt, List<Object> toolProviders) {
            return call(prompt);
        }

        @Override
        public Mono<String> callToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks) {
            return call(prompt);
        }

        @Override
        public Mono<ChatResponse> callToolsResponse(Prompt prompt, List<Object> toolProviders) {
            return call(prompt).map(this::chatResponse);
        }

        @Override
        public Mono<ChatResponse> callToolCallbacksResponse(Prompt prompt, ToolCallback[] toolCallbacks) {
            return call(prompt).map(this::chatResponse);
        }

        @Override
        public Flux<String> streamTools(Prompt prompt, List<Object> toolProviders) {
            return stream(prompt);
        }

        @Override
        public Flux<String> streamToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks) {
            return stream(prompt);
        }

        private ChatResponse chatResponse(String text) {
            return new ChatResponse(List.of(new Generation(new AssistantMessage(text))));
        }

        private String response(DeterministicOutcome outcome) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("action", outcome.action());
            body.put("riskScore", outcome.riskScore());
            body.put("confidence", outcome.confidence());
            body.put("reasoning", "HCAD extreme deterministic " + outcome.kind().name()
                    + " for " + outcome.reasonToken());
            body.put("mitre", "HCAD-EXTREME-TEST");
            try {
                return objectMapper.writeValueAsString(body);
            } catch (Exception ex) {
                throw new IllegalStateException("Unable to serialize deterministic HCAD response", ex);
            }
        }

        private DeterministicOutcome resolveOutcome(Prompt prompt) {
            String text = prompt == null ? "" : prompt.getContents();
            String normalized = text == null ? "" : text.toLowerCase(Locale.ROOT);
            if (matchesScenario(normalized, "model-unavailable")) {
                return DeterministicOutcome.modelUnavailable("model-unavailable");
            }
            if (matchesScenario(normalized, "timeout")) {
                return DeterministicOutcome.timeout("timeout");
            }
            if (matchesScenario(normalized, "parser-failure")) {
                return DeterministicOutcome.parserFailure("parser-failure");
            }
            if (matchesScenario(normalized, "block")) {
                return DeterministicOutcome.block("block");
            }
            if (matchesScenario(normalized, "challenge")) {
                return DeterministicOutcome.challenge("challenge");
            }
            return DeterministicOutcome.allow("allow-default");
        }

        private boolean matchesScenario(String normalizedPrompt, String scenario) {
            if (!StringUtils.hasText(normalizedPrompt) || !StringUtils.hasText(scenario)) {
                return false;
            }
            String normalizedScenario = scenario.trim().toLowerCase(Locale.ROOT);
            return normalizedPrompt.contains("/contexa/test/hcad/protectable/" + normalizedScenario)
                    || normalizedPrompt.contains("/contexa/test/hcad/non-protectable/fanout/" + normalizedScenario)
                    || normalizedPrompt.contains("hcad.extreme." + normalizedScenario)
                    || normalizedPrompt.contains("protectable-" + normalizedScenario)
                    || normalizedPrompt.contains("fanout/" + normalizedScenario);
        }
    }

    private record DeterministicOutcome(
            Kind kind,
            String action,
            double riskScore,
            double confidence,
            String reasonToken
    ) {
        static DeterministicOutcome allow(String token) {
            return new DeterministicOutcome(Kind.ALLOW, "ALLOW", 0.05d, 0.95d, token);
        }

        static DeterministicOutcome challenge(String token) {
            return new DeterministicOutcome(Kind.CHALLENGE, "CHALLENGE", 0.82d, 0.93d, token);
        }

        static DeterministicOutcome block(String token) {
            return new DeterministicOutcome(Kind.BLOCK, "BLOCK", 0.96d, 0.94d, token);
        }

        static DeterministicOutcome parserFailure(String token) {
            return new DeterministicOutcome(Kind.PARSER_FAILURE, "CHALLENGE", 0.80d, 0.20d, token);
        }

        static DeterministicOutcome timeout(String token) {
            return new DeterministicOutcome(Kind.TIMEOUT, "CHALLENGE", 0.80d, 0.20d, token);
        }

        static DeterministicOutcome modelUnavailable(String token) {
            return new DeterministicOutcome(Kind.MODEL_UNAVAILABLE, "CHALLENGE", 0.80d, 0.20d, token);
        }
    }

    private enum Kind {
        ALLOW,
        CHALLENGE,
        BLOCK,
        PARSER_FAILURE,
        TIMEOUT,
        MODEL_UNAVAILABLE
    }

    public static class HcadExtremeTestService {

        @Protectable(
                resourceId = "hcad.extreme.allow",
                resourceUrl = "/contexa/test/hcad/protectable/allow",
                httpMethod = "GET",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> allow(String runId) {
            return response("protectable-allow", runId);
        }

        @Protectable(
                resourceId = "hcad.extreme.challenge",
                resourceUrl = "/contexa/test/hcad/protectable/challenge",
                httpMethod = "GET",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> challenge(String runId) {
            return response("protectable-challenge", runId);
        }

        @Protectable(
                resourceId = "hcad.extreme.block",
                resourceUrl = "/contexa/test/hcad/protectable/block",
                httpMethod = "POST",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> block(String runId) {
            return response("protectable-block", runId);
        }

        @Protectable(
                resourceId = "hcad.extreme.parser-failure",
                resourceUrl = "/contexa/test/hcad/protectable/parser-failure",
                httpMethod = "GET",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> parserFailure(String runId) {
            return response("protectable-parser-failure", runId);
        }

        @Protectable(
                resourceId = "hcad.extreme.timeout",
                resourceUrl = "/contexa/test/hcad/protectable/timeout",
                httpMethod = "GET",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> timeout(String runId) {
            return response("protectable-timeout", runId);
        }

        @Protectable(
                resourceId = "hcad.extreme.model-unavailable",
                resourceUrl = "/contexa/test/hcad/protectable/model-unavailable",
                httpMethod = "GET",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> modelUnavailable(String runId) {
            return response("protectable-model-unavailable", runId);
        }

        private Map<String, Object> response(String scenario, String runId) {
            return Map.of(
                    "scenario", scenario,
                    "runId", runId == null ? "" : runId,
                    "source", "hcad-extreme-test");
        }
    }

    @RestController
    @RequestMapping("/contexa/test/hcad")
    public static class HcadExtremeTestController {

        private final HcadExtremeTestService service;
        private final HCADDataStore hcadDataStore;
        private final SecurityContextDataStore securityContextDataStore;
        private final BaselineDataStore baselineDataStore;

        public HcadExtremeTestController(
                HcadExtremeTestService service,
                ObjectProvider<HCADDataStore> hcadDataStoreProvider,
                ObjectProvider<SecurityContextDataStore> securityContextDataStoreProvider,
                ObjectProvider<BaselineDataStore> baselineDataStoreProvider) {
            this.service = service;
            this.hcadDataStore = hcadDataStoreProvider == null ? null : hcadDataStoreProvider.getIfAvailable();
            this.securityContextDataStore = securityContextDataStoreProvider == null
                    ? null
                    : securityContextDataStoreProvider.getIfAvailable();
            this.baselineDataStore = baselineDataStoreProvider == null
                    ? null
                    : baselineDataStoreProvider.getIfAvailable();
        }

        @PostMapping("/seed/redline")
        public ResponseEntity<Map<String, Object>> seedRedline(
                HttpServletRequest request,
                Authentication authentication,
                @RequestParam(required = false) String runId) {
            return seedRedlineInternal(request, authentication, runId);
        }

        @GetMapping("/seed/redline")
        public ResponseEntity<Map<String, Object>> seedRedlineGet(
                HttpServletRequest request,
                Authentication authentication,
                @RequestParam(required = false) String runId) {
            return seedRedlineInternal(request, authentication, runId);
        }

        private ResponseEntity<Map<String, Object>> seedRedlineInternal(
                HttpServletRequest request,
                Authentication authentication,
                String runId) {
            String userId = authentication != null ? authentication.getName() : "anonymous";
            String sessionId = sessionId(request);
            long now = System.currentTimeMillis();
            seedEstablishedBaseline(userId);

            if (securityContextDataStore != null && StringUtils.hasText(sessionId)) {
                securityContextDataStore.addSessionAction(sessionId, "AUTHENTICATION_FAILURE");
                securityContextDataStore.addSessionAction(sessionId, "LOGIN_FAILURE");
                securityContextDataStore.addSessionAction(sessionId, "LOGIN_FAILURE");
                securityContextDataStore.setSessionPreviousPath(sessionId, "/contexa/test/hcad/seed/origin");
                securityContextDataStore.setSessionLastRequestTime(sessionId, now);
            }
            if (securityContextDataStore != null && StringUtils.hasText(userId)) {
                securityContextDataStore.setPreviousPath(userId, "/contexa/test/hcad/seed/origin");
                securityContextDataStore.setLastRequestTime(userId, now);
            }
            if (hcadDataStore != null && StringUtils.hasText(sessionId)) {
                hcadDataStore.saveSessionMetadata(sessionId, Map.of(
                        "impossibleTravel", true,
                        "baselineConfidence", 0.95d,
                        "hcadExtremeRunId", firstText(runId, request != null ? request.getHeader(RUN_ID_HEADER) : null, "")));
            }
            if (hcadDataStore != null && StringUtils.hasText(userId)) {
                for (int i = 0; i < 15; i++) {
                    hcadDataStore.recordRequest(userId, now - Duration.ofSeconds(10).toMillis() + i);
                }
            }
            return ResponseEntity.ok(Map.of(
                    "seeded", true,
                    "runId", firstText(runId, request != null ? request.getHeader(RUN_ID_HEADER) : null, ""),
                    "userId", userId,
                    "sessionId", sessionId == null ? "" : sessionId));
        }

        @PostMapping("/seed/baseline/established")
        public ResponseEntity<Map<String, Object>> seedEstablishedBaseline(
                HttpServletRequest request,
                Authentication authentication,
                @RequestParam(required = false) String runId) {
            String userId = authentication != null ? authentication.getName() : "anonymous";
            boolean saved = seedEstablishedBaseline(userId);
            return ResponseEntity.ok(Map.of(
                    "baselineSeeded", saved,
                    "baselineProfile", "established-office",
                    "runId", firstText(runId, request != null ? request.getHeader(RUN_ID_HEADER) : null, ""),
                    "userId", userId));
        }

        @PostMapping("/seed/baseline/insufficient")
        public ResponseEntity<Map<String, Object>> seedInsufficientBaseline(
                HttpServletRequest request,
                Authentication authentication,
                @RequestParam(required = false) String runId) {
            String userId = authentication != null ? authentication.getName() : "anonymous";
            boolean saved = seedBaseline(userId, 3L, "insufficient-office");
            return ResponseEntity.ok(Map.of(
                    "baselineSeeded", saved,
                    "baselineProfile", "insufficient-office",
                    "runId", firstText(runId, request != null ? request.getHeader(RUN_ID_HEADER) : null, ""),
                    "userId", userId));
        }

        @GetMapping("/seed/baseline/established")
        public ResponseEntity<Map<String, Object>> seedEstablishedBaselineGet(
                HttpServletRequest request,
                Authentication authentication,
                @RequestParam(required = false) String runId) {
            return seedEstablishedBaseline(request, authentication, runId);
        }

        @GetMapping("/seed/baseline/insufficient")
        public ResponseEntity<Map<String, Object>> seedInsufficientBaselineGet(
                HttpServletRequest request,
                Authentication authentication,
                @RequestParam(required = false) String runId) {
            return seedInsufficientBaseline(request, authentication, runId);
        }

        @GetMapping("/protectable/allow")
        public Map<String, Object> protectableAllow(HttpServletRequest request) {
            return service.allow(runId(request));
        }

        @GetMapping("/protectable/challenge")
        public Map<String, Object> protectableChallenge(HttpServletRequest request) {
            return service.challenge(runId(request));
        }

        @PostMapping("/protectable/block")
        public Map<String, Object> protectableBlock(HttpServletRequest request) {
            return service.block(runId(request));
        }

        @GetMapping("/protectable/parser-failure")
        public Map<String, Object> protectableParserFailure(HttpServletRequest request) {
            return service.parserFailure(runId(request));
        }

        @GetMapping("/protectable/timeout")
        public Map<String, Object> protectableTimeout(HttpServletRequest request) {
            return service.timeout(runId(request));
        }

        @GetMapping("/protectable/model-unavailable")
        public Map<String, Object> protectableModelUnavailable(HttpServletRequest request) {
            return service.modelUnavailable(runId(request));
        }

        @GetMapping("/non-protectable/fanout/{id}")
        public Map<String, Object> fanout(
                @PathVariable String id,
                HttpServletRequest request,
                @RequestParam(required = false) String result) {
            return Map.of(
                    "scenario", "non-protectable-fanout",
                    "id", id,
                    "result", result == null ? "" : result,
                    "runId", runId(request));
        }

        @GetMapping("/non-protectable/fanout/{scenario}/{id}")
        public Map<String, Object> fanoutPathParameter(
                @PathVariable String scenario,
                @PathVariable String id,
                HttpServletRequest request,
                @RequestParam(required = false) String result) {
            return Map.of(
                    "scenario", "non-protectable-fanout-path-parameter",
                    "llmScenario", scenario,
                    "id", id,
                    "result", result == null ? "" : result,
                    "runId", runId(request));
        }

        private String runId(HttpServletRequest request) {
            String value = firstText(
                    request != null ? request.getHeader(RUN_ID_HEADER) : null,
                    request != null ? request.getParameter("runId") : null);
            return value == null ? "" : value;
        }

        private String sessionId(HttpServletRequest request) {
            if (request == null) {
                return null;
            }
            HttpSession session = request.getSession(false);
            return session == null ? null : session.getId();
        }

        private boolean seedEstablishedBaseline(String userId) {
            return seedBaseline(userId, 40L, "established-office");
        }

        private boolean seedBaseline(String userId, long updateCount, String profile) {
            if (baselineDataStore == null || !StringUtils.hasText(userId)) {
                return false;
            }
            Map<String, Long> frequencies = new HashMap<>();
            frequencies.put("ip:10.10.0.0/16", updateCount);
            frequencies.put("path:admin.dashboard", updateCount);
            frequencies.put("ua:Firefox/120", updateCount);
            frequencies.put("os:Linux", updateCount);
            frequencies.put("browser:Firefox", updateCount);
            frequencies.put("auth:password", updateCount);
            frequencies.put("action:READ", updateCount);
            frequencies.put("resource:ADMIN_DASHBOARD", updateCount);

            BaselineVector baseline = BaselineVector.builder()
                    .userId(userId)
                    .avgTrustScore(0.98d)
                    .avgRequestCount(updateCount)
                    .updateCount(updateCount)
                    .lastUpdated(Instant.now())
                    .normalIpRanges(new String[]{"10.10.0.0/16"})
                    .normalIpBands(new String[]{"10.10.0.0/16"})
                    .normalAccessHours(new Integer[]{9, 10, 11, 13, 14, 15})
                    .normalAccessDays(new Integer[]{1, 2, 3, 4, 5})
                    .frequentPaths(new String[]{"/contexa/admin/dashboard", "/contexa/admin/users"})
                    .frequentResourceFamilies(new String[]{"ADMIN_DASHBOARD", "USER_ADMINISTRATION"})
                    .normalUserAgents(new String[]{"Firefox/120"})
                    .normalOperatingSystems(new String[]{"Linux"})
                    .normalBrowsers(new String[]{"Firefox"})
                    .normalAuthenticationTypes(new String[]{"password"})
                    .frequentActionFamilies(new String[]{"READ"})
                    .elementFrequencies(frequencies)
                    .build();
            baselineDataStore.saveUserBaseline(userId, baseline);
            if (hcadDataStore != null) {
                hcadDataStore.saveSessionMetadata("hcad-extreme-baseline:" + userId, Map.of(
                        "profile", profile,
                        "updateCount", updateCount,
                        "seededAt", Instant.now().toString()));
            }
            return true;
        }
    }

    private static String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private static void demoteProductionLlmPrimary(ConfigurableListableBeanFactory beanFactory, String beanName) {
        if (beanFactory != null && beanFactory.containsBeanDefinition(beanName)) {
            beanFactory.getBeanDefinition(beanName).setPrimary(false);
        }
    }
}
