package io.contexa.demo.observation.prompt.service.impl;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate.BehaviorAnalysis;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate.SessionContext;
import io.contexa.contexacore.util.SensitiveValueSanitizer;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptSnapshot;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.demo.observation.prompt.dto.BaselineHistoryEvidence;
import io.contexa.demo.observation.prompt.dto.PromptContextEvidence;
import io.contexa.demo.observation.prompt.dto.PromptReferenceEvidence;
import io.contexa.demo.observation.prompt.dto.RagSearchEvidence;
import io.contexa.demo.observation.prompt.dto.SessionHistoryEvidence;
import io.contexa.demo.observation.prompt.service.PromptContextProjection;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.ai.document.Document;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
@Profile("contexa")
public class NativePromptContextProjection implements PromptContextProjection {

    private static final int MAX_REFERENCES = 20;
    private static final Set<String> RETRIEVAL_STATES = Set.of(
            "AVAILABLE", "ZERO_RESULTS", "PERMISSION_FILTERED", "NOT_REQUESTED", "BUDGET_EXPIRED", "UNAVAILABLE", "TIMEOUT");
    private final DocumentCodec documents;

    public NativePromptContextProjection(DocumentCodec documents) {
        this.documents = documents;
    }

    @Override
    public PromptContextEvidence project(SealedEvidencePromptSnapshot snapshot) {
        SessionHistoryEvidence session = null;
        if (snapshot.sessionContext() instanceof SessionContext source) {
            session = new SessionHistoryEvidence(source.getRequestCount(), source.getSessionAgeMinutes(),
                    safeMethod(source.getAuthMethod()));
        }
        BaselineHistoryEvidence baseline = null;
        if (snapshot.behaviorAnalysis() instanceof BehaviorAnalysis source) {
            baseline = new BaselineHistoryEvidence(source.isPersonalBaselineAvailable(),
                    source.isPersonalBaselineEstablished(), source.isOrganizationBaselineAvailable(),
                    source.isOrganizationBaselineEstablished(), source.getBaselineUpdateCount());
        }
        List<Document> attached = snapshot.relatedDocuments();
        List<PromptReferenceEvidence> references = attached == null ? List.of()
                : attached.stream().limit(MAX_REFERENCES).map(this::reference).toList();
        RagSearchEvidence retrieval = retrieval(snapshot);
        return new PromptContextEvidence("CAPTURE_TRACE_READ_AT_LAYER1_COMPLETION", Instant.now(), session,
                baseline, retrieval == null ? "NOT_OBSERVED" : retrieval.state(),
                attached == null ? null : attached.size(), references,
                attached != null && attached.size() > MAX_REFERENCES, retrieval);
    }

    private RagSearchEvidence retrieval(SealedEvidencePromptSnapshot snapshot) {
        if (snapshot.securityEvent() == null || snapshot.securityEvent().getMetadata() == null) {
            return null;
        }
        Map<String, Object> metadata = snapshot.securityEvent().getMetadata();
        Object state = metadata.get("ragRetrievalState");
        if (!(state instanceof String text) || !RETRIEVAL_STATES.contains(text)) {
            return null;
        }
        return new RagSearchEvidence("NATIVE_EVENT_METADATA_AT_LAYER1_COMPLETION_NOT_PROVIDER_CALL_COUNT",
                text, flag(metadata, "ragSearchExecuted"), count(metadata, "ragSearchQueryCount"),
                count(metadata, "ragCandidateDocumentCount"), count(metadata, "ragAuthorizedDocumentCount"),
                count(metadata, "ragDeniedDocumentCount"), flag(metadata, "ragProjectedToFinalPrompt"));
    }

    private Boolean flag(Map<String, Object> metadata, String key) {
        return metadata.get(key) instanceof Boolean value ? value : null;
    }

    private Integer count(Map<String, Object> metadata, String key) {
        Object value = metadata.get(key);
        if (value instanceof Integer count && count >= 0) {
            return count;
        }
        if (value instanceof Long count && count >= 0 && count <= Integer.MAX_VALUE) {
            return count.intValue();
        }
        return null;
    }

    private PromptReferenceEvidence reference(Document source) {
        if (source == null) {
            return new PromptReferenceEvidence(null, null, null, null, null);
        }
        Double score = source.getScore();
        return new PromptReferenceEvidence(hash(source.getId()), hash(source.getText()),
                score != null && Double.isFinite(score) ? score : null,
                metadataHash(source, VectorDocumentMetadata.ID),
                metadataHash(source, VectorDocumentMetadata.ARTIFACT_ID));
    }

    private String metadataHash(Document source, String key) {
        Object value = source.getMetadata().get(key);
        return value instanceof String text && !text.isBlank() ? documents.hash(text) : null;
    }

    private String hash(String value) {
        return value == null ? null : documents.hash(value);
    }

    private String safeMethod(String value) {
        if (value == null) {
            return null;
        }
        String safe = SensitiveValueSanitizer.sanitizeText(value);
        return safe.substring(0, Math.min(safe.length(), 128));
    }
}
