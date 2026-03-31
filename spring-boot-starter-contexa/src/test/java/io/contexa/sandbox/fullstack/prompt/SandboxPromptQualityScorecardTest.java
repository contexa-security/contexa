package io.contexa.sandbox.fullstack.prompt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxPromptQualityScorecardTest {

    @Test
    @DisplayName("progression scorecard는 4차 이상 N차 회차도 역행 없이 검증해야 한다")
    void shouldEvaluateAllRoundsNotOnlyFirstThree() {
        // 4차 이상 반복에서도 같은 규칙으로 누적을 검증해야 한다.
        // 3차까지만 보면 장기 benchmark에서 후반 회차 역행이 숨어 버린다.
        SandboxPromptQualityScorecard scorecard = SandboxPromptQualityScorecard.evaluateProgression(
                "N차 progression",
                List.of(
                        snapshot("request-1", 0, 1, true),
                        snapshot("request-2", 1, 2, true),
                        snapshot("request-3", 2, 3, true),
                        snapshot("request-4", 3, 4, true)));

        assertThat(scorecard.failedChecks()).isEmpty();
        assertThat(scorecard.passRatePercent()).isEqualTo(100.0d);
    }

    @Test
    @DisplayName("progression scorecard는 후반 회차 relatedDocuments 역행을 실패로 잡아야 한다")
    void shouldFailWhenLaterRoundRegresses() {
        // 4차에서 memory trace가 줄어드는 것은 저장 누락, retrieval 실패, contamination 정리 오류 같은
        // 구현 결함의 신호이므로 즉시 실패로 잡아야 한다.
        SandboxPromptQualityScorecard scorecard = SandboxPromptQualityScorecard.evaluateProgression(
                "N차 progression regression",
                List.of(
                        snapshot("request-1", 0, 1, true),
                        snapshot("request-2", 1, 2, true),
                        snapshot("request-3", 2, 3, true),
                        snapshot("request-4", 1, 4, true)));

        assertThat(scorecard.failedChecks())
                .extracting(SandboxPromptQualityScorecard.CheckResult::label)
                .anyMatch(label -> label.contains("relatedDocuments"));
    }

    private SandboxPromptTraceSnapshot snapshot(
            String requestId,
            int relatedDocumentCount,
            int observationCount,
            boolean includeObservedPatternSection) {
        List<Document> relatedDocuments = java.util.stream.IntStream.range(0, relatedDocumentCount)
                .mapToObj(index -> new Document("related-doc-" + index, Map.of(
                        "requestPath", "/admin/api/security-test/sensitive/resource-001",
                        "userId", "sandbox-admin@example.com",
                        "retrievalPurpose", "security_investigation")))
                .toList();

        StringBuilder userPrompt = new StringBuilder()
                .append("=== CURRENT REQUEST AND EVENT ===\n")
                .append("RequestPath: /admin/api/security-test/sensitive/resource-001\n")
                .append("MfaVerified: true\n")
                .append("AuthorizationEffect: ALLOW\n")
                .append("Sensitivity: HIGH\n");
        if (includeObservedPatternSection) {
            userPrompt.append("=== OBSERVED WORK PATTERN CONTEXT ===\n");
        }
        userPrompt.append("=== PERSONAL WORK PROFILE ===\n")
                .append("WorkProfileSummary: Window 7d | Observations ")
                .append(observationCount)
                .append('\n');
        if (relatedDocumentCount == 0) {
            userPrompt.append("PROVISIONAL\n");
        }

        return new SandboxPromptTraceSnapshot(
                requestId,
                Instant.now(),
                null,
                null,
                null,
                relatedDocuments,
                null,
                "You are a Zero Trust security analyst AI.\n=== DECISION ===\n<output_format>\n\"action\":\"ALLOW|CHALLENGE|BLOCK|ESCALATE\"",
                userPrompt.toString(),
                Map.of(),
                null);
    }
}
