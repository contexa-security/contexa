package io.contexa.contexacore.autonomous.saas.threat;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackSnapshot;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

class ThreatSignalMatcherServiceTest {

    private final ThreatSignalMatcherService service = new ThreatSignalMatcherService();

    @Test
    void buildContextSelectsRelevantSignalsForAuthenticationAttack() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-001")
                .timestamp(LocalDateTime.of(2026, 3, 17, 9, 30))
                .sourceIp("203.0.113.10")
                .metadata(Map.of(
                        "requestPath", "/login",
                        "geoCountry", "KR",
                        "failedLoginAttempts", 5,
                        "isSensitiveResource", true))
                .build();
        SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityPromptTemplate.BehaviorAnalysis();
        ThreatIntelligenceMatchContext context = service.buildContext(event, behaviorAnalysis, List.of(
                signal("signal-auth", "credential_abuse", "KR", List.of("authentication"), List.of("failed_login_burst")),
                signal("signal-admin", "privilege_abuse", "US", List.of("administration"), List.of("privileged_flow"))), 3);

        assertThat(context.hasMatches()).isTrue();
        assertThat(context.matchedSignals()).hasSize(1);
        assertThat(context.matchedSignals().get(0).signal().signalKey()).isEqualTo("signal-auth");
        assertThat(context.matchedSignals().get(0).matchedFacts()).contains("The request is on the authentication surface with repeated login failures, which matches credential abuse campaigns.");
    }

    @Test
    void buildContextEscalatesForStrongSessionHijackOverlap() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-002")
                .timestamp(LocalDateTime.of(2026, 3, 17, 10, 0))
                .metadata(Map.of(
                        "requestPath", "/session/refresh",
                        "geoCountry", "KR"))
                .build();
        SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setContextBindingHashMismatch(true);

        ThreatIntelligenceMatchContext context = service.buildContext(event, behaviorAnalysis, List.of(
                signal("signal-session", "session_hijack", "KR", List.of("session"), List.of("session_integrity_risk"))), 3);

        assertThat(context.hasMatches()).isTrue();
        assertThat(context.matchedSignals().get(0).matchedFacts()).contains("The current session shows a binding anomaly that is consistent with session hijacking attempts.");
    }

    @Test
    void buildKnowledgeContextSelectsComparableCasesWithoutInjectingScores() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-003")
                .timestamp(LocalDateTime.of(2026, 3, 17, 11, 0))
                .metadata(Map.of(
                        "requestPath", "/login",
                        "geoCountry", "KR",
                        "failedLoginAttempts", 4,
                        "isSensitiveResource", true))
                .build();
        SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityPromptTemplate.BehaviorAnalysis();

        ThreatKnowledgePackMatchContext context = service.buildKnowledgeContext(event, behaviorAnalysis, List.of(
                knowledgeCase("knowledge-auth", "credential_abuse", "KR", List.of("authentication"), List.of("failed_login_burst")),
                knowledgeCase("knowledge-admin", "privilege_abuse", "US", List.of("administration"), List.of("privileged_flow"))), 2);

        assertThat(context.hasMatches()).isTrue();
        assertThat(context.matchedCases()).hasSize(1);
        assertThat(context.matchedCases().get(0).knowledgeCase().knowledgeKey()).isEqualTo("knowledge-auth");
        assertThat(context.matchedCases().get(0).matchedFacts())
                .contains("The current request targets the authentication surface, which appears in previous reviewed cases.")
                .contains("The current request includes repeated login failures, which matches prior reviewed cases.")
                .doesNotContain("SuggestedRiskUplift")
                .doesNotContain("RecommendedAction");
    }

    private ThreatIntelligenceSnapshot.ThreatSignalItem signal(
            String signalKey,
            String threatClass,
            String geoCountry,
            List<String> targetSurfaceHints,
            List<String> signalTags) {
        return new ThreatIntelligenceSnapshot.ThreatSignalItem(
                signalKey,
                "ACTIVE",
                threatClass,
                geoCountry,
                List.of("Initial Access"),
                targetSurfaceHints,
                signalTags,
                4,
                6,
                LocalDateTime.of(2026, 3, 17, 8, 0),
                LocalDateTime.now().minusMinutes(20),
                LocalDateTime.now().plusHours(2),
                "Cross-tenant campaign detected.");
    }

    private ThreatKnowledgePackSnapshot.KnowledgeCaseItem knowledgeCase(
            String knowledgeKey,
            String threatClass,
            String geoCountry,
            List<String> targetSurfaceHints,
            List<String> signalTags) {
        return new ThreatKnowledgePackSnapshot.KnowledgeCaseItem(
                "signal-" + knowledgeKey,
                knowledgeKey,
                threatClass,
                geoCountry,
                targetSurfaceHints,
                signalTags,
                List.of("Multiple tenants observed the same attack pattern."),
                List.of("Attackers pivoted after authentication pressure."),
                List.of("Account takeover confirmed after investigation."),
                List.of("Ignore ordinary password reset bursts."),
                "REINFORCED",
                List.of("Confirmed attack outcomes are reusable memories for this case."),
                "Credential abuse campaign across finance tenants",
                "Prior cases converged on account takeover after burst failures.",
                LocalDateTime.of(2026, 3, 17, 10, 0),
                4,
                6,
                "MATURE",
                List.of("Tenant-local memory contains reinforced attack cases and hard negatives."),
                "POSITIVE_SHIFT",
                List.of("After knowledge promotion, protective review increased on similar cases."),
                "REASONING_READY",
                List.of("Objective-bound reasoning memory is reusable at runtime."),
                "PROMOTED",
                "Promoted for runtime AI use because the case is validated and backed by reusable tenant evidence.",
                List.of("Promotion gate confirmed validated outcome evidence."));
    }
}
