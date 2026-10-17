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
package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import org.springframework.ai.document.Document;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.TimeZone;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.GZIPInputStream;

/**
 * Renders the security decision prompt from the golden inputs: real sealed evidence of the showcase measurement
 * cases and of one engine template relearn step (N-K5-2), turned back into renderer inputs. The canonical context is
 * deserialized as sealed; the request facts,
 * authentication state, baseline summary and retrieval counts go back into the event metadata under the keys the
 * sealed evidence assembler read them from; the retrieval summaries become documents; the past denied decisions the
 * sealed render drew, which its execution metadata keeps and its retrieval results do not, go back under the event
 * key the render read them from (N-K5-2). The behaviour analysis is not
 * sealed; unless a caller gives one, it is built from the case's learning evidence (the baselines its source run held)
 * the way the decision layers build it (N-GOLD-1). The prompts come from the template the way the decision request
 * sends them.
 */
final class SecurityDecisionGoldenRender {

    static final String RESOURCE = "prompt-bundles/golden/cortex.security-decision/case-inputs.json.gz";
    static final List<PromptBudgetProfile> PROFILES =
            List.of(PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT);

    /**
     * Summary keys of sealed retrieval documents that the assembler renamed, mapped back to the metadata key it read
     * first ({@code SealedEvidencePackageAssembler.ragDocumentSummary}).
     */
    private static final Map<String, String> DOCUMENT_METADATA_KEYS = Map.of(
            "authorization", VectorDocumentMetadata.AUTHORIZATION_DECISION,
            "purpose", VectorDocumentMetadata.PURPOSE_MATCH,
            "retrievalPolicy", VectorDocumentMetadata.RETRIEVAL_POLICY_SUMMARY);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .findAndRegisterModules();

    private final byte[] content;
    private final JsonNode document;

    private SecurityDecisionGoldenRender(byte[] content, JsonNode document) {
        this.content = content;
        this.document = document;
    }

    static SecurityDecisionGoldenRender load() {
        try (InputStream input = SecurityDecisionGoldenRender.class.getClassLoader().getResourceAsStream(RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("Golden inputs are missing: " + RESOURCE);
            }
            byte[] content;
            try (GZIPInputStream gzip = new GZIPInputStream(input)) {
                content = gzip.readAllBytes();
            }
            return new SecurityDecisionGoldenRender(content, OBJECT_MAPPER.readTree(content));
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    String contentSha256() {
        return PromptBundleHashes.sha256Hex(content);
    }

    Map<String, String> excludedCases() {
        Map<String, String> excluded = new LinkedHashMap<>();
        document.path("excludedCases").fields().forEachRemaining(entry -> excluded.put(entry.getKey(), entry.getValue().asText()));
        return excluded;
    }

    List<JsonNode> cases() {
        List<JsonNode> cases = new ArrayList<>();
        document.path("cases").forEach(cases::add);
        cases.sort(Comparator.comparing(node -> node.path("caseKey").asText()));
        return cases;
    }

    /**
     * Renders in UTC, the time zone of the showcase engine the inputs were sealed on, so that times in the prompt do
     * not depend on the machine that runs the build.
     */
    RenderedCase render(JsonNode goldenCase, PromptBudgetProfile profile) {
        return render(goldenCase, profile, new TieredStrategyProperties());
    }

    /** Renders with the given settings (the bundle the configuration chooses, W3-16, for example). */
    RenderedCase render(JsonNode goldenCase, PromptBudgetProfile profile, TieredStrategyProperties properties) {
        return render(goldenCase, profile, properties, null);
    }

    /** Renders the bundle the given selector chooses (W3-16). */
    RenderedCase render(JsonNode goldenCase, PromptBudgetProfile profile, PromptBundleSelector selector) {
        return renderInZone(goldenCase, profile, new TieredStrategyProperties(), null, Map.of(), selector);
    }

    /** Renders with the given settings and a behaviour analysis (the threat matches of W3-6, for example). */
    RenderedCase render(JsonNode goldenCase, PromptBudgetProfile profile, TieredStrategyProperties properties,
                        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis) {
        return render(goldenCase, profile, properties, behaviorAnalysis, Map.of());
    }

    /** Renders with request parameters as well (W3-7: the model a request names). */
    RenderedCase render(JsonNode goldenCase, PromptBudgetProfile profile, TieredStrategyProperties properties,
                        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
                        Map<String, String> requestParameters) {
        return renderInZone(goldenCase, profile, properties, behaviorAnalysis, requestParameters, null);
    }

    private RenderedCase renderInZone(JsonNode goldenCase, PromptBudgetProfile profile,
                                      TieredStrategyProperties properties,
                                      SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
                                      Map<String, String> requestParameters, PromptBundleSelector selector) {
        TimeZone original = TimeZone.getDefault();
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        try {
            return renderInDefaultZone(goldenCase, profile, properties, behaviorAnalysis, requestParameters, selector);
        }
        finally {
            TimeZone.setDefault(original);
        }
    }

    private RenderedCase renderInDefaultZone(JsonNode goldenCase, PromptBudgetProfile profile,
                                             TieredStrategyProperties properties,
                                             SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
                                             Map<String, String> requestParameters, PromptBundleSelector selector) {
        CanonicalSecurityContext canonicalContext = new CanonicalSecurityContextSerializer(OBJECT_MAPPER)
                .deserialize(goldenCase.path("canonicalContext").toString());
        if (canonicalContext == null) {
            throw new IllegalStateException("Canonical context of " + goldenCase.path("caseKey").asText() + " does not deserialize");
        }
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                properties,
                event -> Optional.of(canonicalContext),
                new PromptContextComposer(),
                selector,
                null,
                null);
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(sections);
        SecurityEvent event = event(goldenCase);
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis = behaviorAnalysis != null ? behaviorAnalysis
                : SecurityDecisionGoldenLearning.analysis(goldenCase, event, OBJECT_MAPPER);
        SecurityDecisionRequest request = new SecurityDecisionRequest(new SecurityDecisionContext(
                event,
                session(goldenCase),
                analysis,
                documents(goldenCase)));
        request.withParameter("promptBudgetProfile", profile.profileKey());
        request.withParameter("structuredOutputMode", StructuredOutputMode.VALIDATED_CONVERTER.name());
        requestParameters.forEach(request::withParameter);
        String systemText = template.generateSystemPrompt(request, null);
        String userText = template.generateUserPrompt(request, null);
        PromptExecutionMetadata executionMetadata = template.buildPromptExecutionMetadata(request, systemText, userText);
        // The render keeps its own copy of the context; the copy it used (decision facts included) travels with
        // the event for the sealed evidence.
        Object used = event.getMetadata().get("sealedEvidence.canonicalContext");
        return new RenderedCase(goldenCase.path("caseKey").asText(), profile, systemText, userText,
                used instanceof CanonicalSecurityContext context ? context : null, executionMetadata);
    }

    static String digest(List<RenderedCase> rendered) {
        StringBuilder text = new StringBuilder();
        for (RenderedCase item : rendered) {
            text.append("case=").append(item.caseKey()).append('\n')
                    .append("profile=").append(item.profile().name()).append('\n')
                    .append("--- system ---\n").append(item.systemText()).append('\n')
                    .append("--- user ---\n").append(item.userText()).append('\n');
        }
        return PromptBundleHashes.sha256Hex(PromptBundleHashes.normalizeText(text.toString()));
    }

    private static SecurityEvent event(JsonNode goldenCase) {
        JsonNode facts = goldenCase.path("requestFacts");
        SecurityEvent event = SecurityEvent.builder()
                .eventId(text(facts, "requestId"))
                .timestamp(Instant.parse(goldenCase.path("source").path("requestCompanyTime").asText()))
                .userId(text(facts, "userId"))
                .sessionId(text(facts, "sessionId"))
                .sourceIp(text(facts, "clientIp"))
                .userAgent(text(facts, "userAgent"))
                .build();
        putAll(event, facts);
        putAll(event, goldenCase.path("authState"));
        putAll(event, goldenCase.path("baselineSnapshot"));
        Iterator<Map.Entry<String, JsonNode>> retrieval = goldenCase.path("ragResults").fields();
        while (retrieval.hasNext()) {
            Map.Entry<String, JsonNode> entry = retrieval.next();
            if (!"relatedDocuments".equals(entry.getKey())) {
                event.addMetadata(entry.getKey(), OBJECT_MAPPER.convertValue(entry.getValue(), Object.class));
            }
        }
        // N-K5-2: the decisions that did not allow, as the sealed render drew them, under the key the render reads.
        JsonNode denied = goldenCase.path("pastDeniedDecisions");
        if (denied.isArray()) {
            event.addMetadata(PastDeniedDecisions.EVENT_METADATA_KEY, OBJECT_MAPPER.convertValue(denied, Object.class));
        }
        return event;
    }

    private static SecurityDecisionStandardPromptTemplate.SessionContext session(JsonNode goldenCase) {
        SecurityDecisionStandardPromptTemplate.SessionContext session = new SecurityDecisionStandardPromptTemplate.SessionContext();
        session.setUserId(text(goldenCase.path("requestFacts"), "userId"));
        session.setSessionId(text(goldenCase.path("requestFacts"), "sessionId"));
        session.setAuthMethod(text(goldenCase.path("authState"), "authMethod"));
        return session;
    }

    private static List<Document> documents(JsonNode goldenCase) {
        List<Document> documents = new ArrayList<>();
        for (JsonNode summary : goldenCase.path("ragResults").path("relatedDocuments")) {
            Map<String, Object> metadata = new LinkedHashMap<>();
            summary.fields().forEachRemaining(entry -> {
                if (!"textPreview".equals(entry.getKey()) && !"textLength".equals(entry.getKey())) {
                    metadata.put(DOCUMENT_METADATA_KEYS.getOrDefault(entry.getKey(), entry.getKey()),
                            OBJECT_MAPPER.convertValue(entry.getValue(), Object.class));
                }
            });
            putClock(metadata);
            String preview = summary.path("textPreview").asText("");
            documents.add(new Document(summary.path("id").asText(), preview.isBlank() ? " " : preview, metadata));
        }
        return documents;
    }

    /**
     * The hour and day of week of a past record, which its sealed summary does not keep: the engine wrote them with the
     * record's timestamp from the same local time of the event (SecurityDecisionPostProcessor), so the timestamp
     * gives them back. The closest past record of the baseline comparison is read on the hour (N-GOLD-1).
     */
    private static void putClock(Map<String, Object> metadata) {
        if (metadata.containsKey("hour") || !(metadata.get("timestamp") instanceof String timestamp)) {
            return;
        }
        try {
            LocalDateTime at = LocalDateTime.parse(timestamp);
            metadata.put("hour", at.getHour());
            metadata.put("dayOfWeek", at.getDayOfWeek().getValue());
        }
        catch (DateTimeParseException exception) {
            throw new IllegalStateException("Past record timestamp is no local date and time: " + timestamp, exception);
        }
    }

    private static void putAll(SecurityEvent event, JsonNode node) {
        node.fields().forEachRemaining(entry ->
                event.addMetadata(entry.getKey(), OBJECT_MAPPER.convertValue(entry.getValue(), Object.class)));
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isMissingNode() || value.isNull() ? null : value.asText();
    }

    /** One rendered case, with the canonical context the render filled (decision facts included). */
    record RenderedCase(String caseKey, PromptBudgetProfile profile, String systemText, String userText,
                        CanonicalSecurityContext canonicalContext, PromptExecutionMetadata executionMetadata) {
    }
}
