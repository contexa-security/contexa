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
package io.contexa.contexacore.verification.replay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.springframework.ai.document.Document;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The inputs of a sealed decision as its prompt was drawn from them (V-2.2 of the v21 plan): the event of the request
 * (its facts, authentication state, baseline summary and retrieval state), the session, the past records the search
 * returned and the canonical context with its decision facts. The event carries a replay id of its own, so that nothing
 * the replay writes is taken for the request it replays.
 *
 * @param event            the request's event under the replay id
 * @param session          the session of the request
 * @param documents        the past records the sealed search returned
 * @param canonicalContext the sealed canonical context
 */
public record SealedDecisionReplayInputs(SecurityEvent event, SecurityDecisionStandardPromptTemplate.SessionContext session,
                                         List<Document> documents, CanonicalSecurityContext canonicalContext) {

    /** The prefix of every replay's request id. */
    public static final String REPLAY_ID_PREFIX = "replay-";

    /**
     * Summary keys of sealed retrieval documents that the assembler renamed, mapped back to the metadata key it read
     * first ({@code SealedEvidencePackageAssembler.ragDocumentSummary}).
     */
    private static final Map<String, String> DOCUMENT_METADATA_KEYS = Map.of(
            "authorization", VectorDocumentMetadata.AUTHORIZATION_DECISION,
            "purpose", VectorDocumentMetadata.PURPOSE_MATCH,
            "retrievalPolicy", VectorDocumentMetadata.RETRIEVAL_POLICY_SUMMARY);

    /** The inputs of the package, under the replay id; the request time is the canonical context's. */
    public static SealedDecisionReplayInputs of(SealedEvidencePackage sealed, String replayId, ObjectMapper mapper,
                                                CanonicalSecurityContextSerializer serializer) {
        CanonicalSecurityContext context = serializer.deserialize(sealed.getCanonicalContextJson());
        if (context == null) {
            throw new IllegalArgumentException("The sealed package " + sealed.getPackageId()
                    + " has no canonical context to replay");
        }
        JsonNode facts = read(mapper, sealed.getRequestFactsJson());
        JsonNode authState = read(mapper, sealed.getAuthStateJson());
        Instant at = context.getRequestObservedAt() != null ? context.getRequestObservedAt() : sealed.getCapturedAt();
        SecurityEvent event = SecurityEvent.builder()
                .eventId(replayId)
                .timestamp(at)
                .userId(text(facts, "userId"))
                .sessionId(text(facts, "sessionId"))
                .sourceIp(text(facts, "clientIp"))
                .userAgent(text(facts, "userAgent"))
                .build();
        putAll(event, facts, mapper);
        putAll(event, authState, mapper);
        putAll(event, read(mapper, sealed.getBaselineSnapshotJson()), mapper);
        JsonNode retrieval = read(mapper, sealed.getRagResultsJson());
        retrieval.fields().forEachRemaining(entry -> {
            if (!"relatedDocuments".equals(entry.getKey())) {
                event.addMetadata(entry.getKey(), mapper.convertValue(entry.getValue(), Object.class));
            }
        });
        // The decisions that did not allow, as the sealed render drew them, under the key the render reads (N-K5-2).
        JsonNode denied = read(mapper, sealed.getPromptExecutionMetadataJson()).path("supplementalMetadata")
                .path(PromptExecutionMetadata.PROMPT_PAST_DENIED_DECISIONS);
        if (denied.isArray()) {
            event.addMetadata(PastDeniedDecisions.EVENT_METADATA_KEY, mapper.convertValue(denied, Object.class));
        }
        // The replay's own id: what it records is not the request's.
        event.addMetadata("requestId", replayId);
        event.addMetadata("correlationId", replayId);
        event.addMetadata("replayedRequestId", sealed.getCorrelationId());
        event.addMetadata("replayedPackageId", sealed.getPackageId());

        SecurityDecisionStandardPromptTemplate.SessionContext session = new SecurityDecisionStandardPromptTemplate.SessionContext();
        session.setUserId(text(facts, "userId"));
        session.setSessionId(text(facts, "sessionId"));
        session.setAuthMethod(text(authState, "authMethod"));
        return new SealedDecisionReplayInputs(event, session, documents(retrieval, mapper), context);
    }

    /** The baselines the decision was drawn against, for whichever user or organization the analysis asks. */
    public record SealedBaselines(BaselineVector personal, BaselineVector organization) implements BaselineDataStore {

        @Override
        public BaselineVector getUserBaseline(String userId) {
            return personal;
        }

        @Override
        public void saveUserBaseline(String userId, BaselineVector baseline) {
            throw new UnsupportedOperationException("The sealed baselines are read only");
        }

        @Override
        public BaselineVector getOrganizationBaseline(String organizationId) {
            return organization;
        }

        @Override
        public void saveOrganizationBaseline(String organizationId, BaselineVector baseline) {
            throw new UnsupportedOperationException("The sealed baselines are read only");
        }

        @Override
        public Iterable<BaselineVector> listOrganizationBaselines() {
            return organization != null ? List.of(organization) : List.of();
        }

        @Override
        public long countUserBaselines() {
            return personal != null ? 1 : 0;
        }
    }

    private static List<Document> documents(JsonNode retrieval, ObjectMapper mapper) {
        List<Document> documents = new ArrayList<>();
        for (JsonNode summary : retrieval.path("relatedDocuments")) {
            Map<String, Object> metadata = new LinkedHashMap<>();
            summary.fields().forEachRemaining(entry -> {
                if (!"textPreview".equals(entry.getKey()) && !"textLength".equals(entry.getKey())) {
                    metadata.put(DOCUMENT_METADATA_KEYS.getOrDefault(entry.getKey(), entry.getKey()),
                            mapper.convertValue(entry.getValue(), Object.class));
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
     * record's timestamp from the same local time of the event, so the timestamp gives them back.
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
            throw new IllegalArgumentException("Past record timestamp is no local date and time: " + timestamp, exception);
        }
    }

    private static void putAll(SecurityEvent event, JsonNode node, ObjectMapper mapper) {
        node.fields().forEachRemaining(entry ->
                event.addMetadata(entry.getKey(), mapper.convertValue(entry.getValue(), Object.class)));
    }

    private static JsonNode read(ObjectMapper mapper, String json) {
        if (json == null || json.isBlank()) {
            return mapper.createObjectNode();
        }
        try {
            return mapper.readTree(json);
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isMissingNode() || value.isNull() ? null : value.asText();
    }
}
