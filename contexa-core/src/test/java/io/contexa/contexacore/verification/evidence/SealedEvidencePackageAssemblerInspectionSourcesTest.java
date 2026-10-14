package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.PastRecordLineValues;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The sealed package keeps what the prompt inspector compares a prompt with: the fact ids, the event time zone and the
 * retrieval state the render drew, the entries it took out for its budget, and every field a past record line draws.
 */
class SealedEvidencePackageAssemblerInspectionSourcesTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private final SealedEvidencePromptTraceStore traceStore = new SealedEvidencePromptTraceStore();
    private final SealedEvidencePackageAssembler assembler = new SealedEvidencePackageAssembler(
            JSON, new CanonicalSecurityContextSerializer(JSON), new SealedEvidencePackageIntegrity(), traceStore);

    @Test
    void theSealedExecutionMetadataKeepsTheRenderFactsThePromptInspectorReads() throws Exception {
        Map<String, Object> ragState = new LinkedHashMap<>();
        ragState.put("retrievalState", "RETRIEVED");
        ragState.put("relatedDocumentCount", 2);
        Map<String, Object> promptMetadata = new HashMap<>();
        promptMetadata.put("promptFactIds", Map.of("RepeatInSession", "F1", "AuthorizationEffect", "F2"));
        promptMetadata.put("eventTimeZone", "Asia/Seoul");
        promptMetadata.put("promptRagState", ragState);
        promptMetadata.put("omittedSections", List.of("DECISION_FACTS.Travel"));
        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("action", "EXPORT");
        counts.put("sameTarget", 2);
        promptMetadata.put("promptPastRecordCounts", counts);
        promptMetadata.put("promptBaselineStatus", "PROVISIONAL");

        SealedEvidencePackage sealed = seal("req-1", promptMetadata, List.of());

        Map<String, Object> metadata = JSON.readValue(sealed.getPromptExecutionMetadataJson(), MAP);
        // R1b-10: no check reads the fact ids, so the package does not keep them.
        assertThat(metadata).doesNotContainKey("promptFactIds");
        assertThat(metadata.get("eventTimeZone")).isEqualTo("Asia/Seoul");
        assertThat(metadata.get("promptRagState")).isEqualTo(ragState);
        assertThat(metadata.get("omittedSections")).isEqualTo(List.of("DECISION_FACTS.Travel"));
        assertThat(metadata.get("promptPastRecordCounts")).isEqualTo(counts);
        assertThat(metadata.get("promptBaselineStatus")).isEqualTo("PROVISIONAL");
    }

    @Test
    void theSealedPastRecordsKeepEveryFieldAPastRecordLineDraws() throws Exception {
        Map<String, Object> recordMetadata = new HashMap<>();
        recordMetadata.put("id", "doc-1");
        recordMetadata.put("timestamp", "2026-10-08T03:17:00Z");
        recordMetadata.put("actionFamily", "EXPORT");
        recordMetadata.put("requestItems", 4831);
        recordMetadata.put("ipBand", "10.40.12.0/24");
        recordMetadata.put("networkZone", "CORPORATE");
        recordMetadata.put("userAgentBrowser", "Chrome/140");
        recordMetadata.put("userAgentOS", "WINDOWS");
        recordMetadata.put("authenticationType", "MFA");
        recordMetadata.put("autonomousAction", "ALLOW");
        Document record = Document.builder().id("doc-1").text("EXPORT /api/projects/PLM-OPS/exports")
                .metadata(recordMetadata).score(0.83d).build();

        SealedEvidencePackage sealed = seal("req-2", Map.of(), List.of(record));

        Map<String, Object> rag = JSON.readValue(sealed.getRagResultsJson(), MAP);
        @SuppressWarnings("unchecked")
        Map<String, Object> summary = ((List<Map<String, Object>>) rag.get("relatedDocuments")).get(0);
        assertThat(summary).containsEntry("actionFamily", "EXPORT")
                .containsEntry("requestItems", 4831)
                .containsEntry("ipBand", "10.40.12.0/24")
                .containsEntry("networkZone", "CORPORATE")
                .containsEntry("userAgentBrowser", "Chrome/140")
                .containsEntry("userAgentOS", "WINDOWS")
                .containsEntry("authenticationType", "MFA")
                .containsEntry("autonomousAction", "ALLOW")
                .containsEntry("score", 0.83d);
    }

    /**
     * R1b-3 (P3 extra 38): a sealed past record reads back into the record the render read, so that the prompt
     * inspector draws the line the render drew. The record holds, for some fields, only keys the render does not read
     * (an allowed flag, a sensitivity, a resource path without its template), so no fallback or derived value may join it.
     */
    @Test
    void aSealedPastRecordReadsBackIntoTheRecordTheRenderRead() {
        Map<String, Object> recordMetadata = new HashMap<>();
        recordMetadata.put("id", "doc-3");
        recordMetadata.put("timestamp", "2026-10-08T03:17:00Z");
        recordMetadata.put("actionFamily", "EXPORT");
        recordMetadata.put("allowed", "true");
        recordMetadata.put("sensitivity", "HIGH");
        recordMetadata.put("resourcePath", "/api/projects/PLM-OPS/exports/77");
        recordMetadata.put("httpMethod", "POST");
        Document record = Document.builder().id("doc-3").text("export of the design archive")
                .metadata(recordMetadata).score(0.8d).build();

        SealedEvidencePackage sealed = seal("req-3", Map.of(), List.of(record));

        LocalDateTime requestTime = LocalDateTime.parse("2026-10-12T03:17:00");
        List<Document> readBack = SealedPastRecordSummary.records(sealed.getRagResultsJson());
        assertThat(PastRecordLineValues.of(readBack, document -> "no", requestTime))
                .isEqualTo(PastRecordLineValues.of(List.of(record), document -> "no", requestTime));
    }

    private SealedEvidencePackage seal(String requestId, Map<String, Object> promptMetadata, List<Document> documents) {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-" + requestId).userId("alice").sessionId("s-1").build();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestId", requestId);
        metadata.put("requestPath", "/api/projects/PLM-OPS/exports");
        event.setMetadata(metadata);

        PromptGenerationResult promptResult = mock(PromptGenerationResult.class);
        when(promptResult.getSystemPrompt()).thenReturn("system prompt");
        when(promptResult.getUserPrompt()).thenReturn("user prompt");
        when(promptResult.getRawSystemPrompt()).thenReturn("system prompt");
        when(promptResult.getRawUserPrompt()).thenReturn("user prompt");
        when(promptResult.getMetadata()).thenReturn(promptMetadata);
        SecurityDecisionContext capture = mock(SecurityDecisionContext.class);
        when(capture.getSecurityEvent()).thenReturn(event);
        when(capture.getRelatedDocuments()).thenReturn(documents);
        traceStore.capture(capture, promptResult);
        traceStore.complete(event);

        SecurityEventContext context = new SecurityEventContext(event);
        ProcessingResult result = ProcessingResult.builder().success(true).build();
        result.setAction("ALLOW");
        context.addMetadata("processingResult", result);
        SealedEvidencePackage sealed = assembler.assemble(context);
        assertThat(sealed).isNotNull();
        return sealed;
    }
}
