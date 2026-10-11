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
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import org.springframework.ai.document.Document;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Instant;
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
 * cases, turned back into renderer inputs. The canonical context is deserialized as sealed; the request facts,
 * authentication state, baseline summary and retrieval counts go back into the event metadata under the keys the
 * sealed evidence assembler read them from; the retrieval summaries become documents. The full behaviour analysis is
 * not sealed, so it is absent here. The prompts come from the template the way the decision request sends them.
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
        TimeZone original = TimeZone.getDefault();
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        try {
            return renderInDefaultZone(goldenCase, profile);
        }
        finally {
            TimeZone.setDefault(original);
        }
    }

    private RenderedCase renderInDefaultZone(JsonNode goldenCase, PromptBudgetProfile profile) {
        CanonicalSecurityContext canonicalContext = new CanonicalSecurityContextSerializer(OBJECT_MAPPER)
                .deserialize(goldenCase.path("canonicalContext").toString());
        if (canonicalContext == null) {
            throw new IllegalStateException("Canonical context of " + goldenCase.path("caseKey").asText() + " does not deserialize");
        }
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                event -> Optional.of(canonicalContext),
                new PromptContextComposer(),
                SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE);
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(sections);
        SecurityDecisionRequest request = new SecurityDecisionRequest(new SecurityDecisionContext(
                event(goldenCase),
                session(goldenCase),
                null,
                documents(goldenCase)));
        request.withParameter("promptBudgetProfile", profile.profileKey());
        request.withParameter("structuredOutputMode", StructuredOutputMode.VALIDATED_CONVERTER.name());
        String systemText = template.generateSystemPrompt(request, null);
        String userText = template.generateUserPrompt(request, null);
        return new RenderedCase(goldenCase.path("caseKey").asText(), profile, systemText, userText);
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
            String preview = summary.path("textPreview").asText("");
            documents.add(new Document(summary.path("id").asText(), preview.isBlank() ? " " : preview, metadata));
        }
        return documents;
    }

    private static void putAll(SecurityEvent event, JsonNode node) {
        node.fields().forEachRemaining(entry ->
                event.addMetadata(entry.getKey(), OBJECT_MAPPER.convertValue(entry.getValue(), Object.class)));
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isMissingNode() || value.isNull() ? null : value.asText();
    }

    record RenderedCase(String caseKey, PromptBudgetProfile profile, String systemText, String userText) {
    }
}
