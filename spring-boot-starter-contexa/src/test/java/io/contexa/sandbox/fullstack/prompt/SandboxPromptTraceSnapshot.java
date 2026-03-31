package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import org.springframework.ai.document.Document;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 실제 웹 요청이 비동기 LLM 파이프라인을 통과하면서 생성한 원본 trace 스냅샷.
 *
 * 검증 대상은 synthetic 객체가 아니라 아래 원본들이다.
 * - SecurityEvent
 * - SessionContext
 * - BehaviorAnalysis
 * - relatedDocuments
 * - PromptGenerationResult(system/user/metadata/promptExecutionMetadata)
 */
public record SandboxPromptTraceSnapshot(
        String requestId,
        Instant capturedAt,
        SecurityEvent event,
        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext,
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
        List<Document> relatedDocuments,
        SandboxRetrievalAuditSnapshot retrievalAudit,
        String systemPrompt,
        String userPrompt,
        Map<String, Object> metadata,
        PromptExecutionMetadata promptExecutionMetadata) {

    public SandboxPromptTraceSnapshot {
        relatedDocuments = relatedDocuments == null ? List.of() : List.copyOf(relatedDocuments);
        metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
    }

    public Map<String, Object> toDiagnosticMap(ObjectMapper objectMapper) {
        Map<String, Object> diagnostic = new LinkedHashMap<>();
        diagnostic.put("requestId", requestId);
        diagnostic.put("capturedAt", capturedAt != null ? capturedAt.toString() : null);
        diagnostic.put("event", objectMapper.convertValue(event, Map.class));
        diagnostic.put("sessionCtx", objectMapper.convertValue(sessionContext, Map.class));
        diagnostic.put("behaviorCtx", objectMapper.convertValue(behaviorAnalysis, Map.class));
        diagnostic.put("relatedDocuments", relatedDocuments.stream()
                .map(document -> objectMapper.convertValue(document, Map.class))
                .toList());
        diagnostic.put("retrievalAudit",
                retrievalAudit != null ? objectMapper.convertValue(retrievalAudit, Map.class) : Map.of());
        diagnostic.put("systemPrompt", systemPrompt);
        diagnostic.put("userPrompt", userPrompt);
        diagnostic.put("metadata", metadata);
        diagnostic.put("promptExecutionMetadata",
                promptExecutionMetadata != null ? objectMapper.convertValue(promptExecutionMetadata, Map.class) : Map.of());
        return diagnostic;
    }
}
