package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRule;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotPlan;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotPlanProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotRenderer;
import io.contexa.contexacore.autonomous.context.registry.InMemoryResourceContextRegistry;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import io.contexa.contexacore.verification.runtime.testsupport.OfficialVerificationTestMessages;
import org.springframework.ai.document.Document;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

final class PromptGovernanceExtremeTestHarness {

    private final ObjectMapper objectMapper = new ObjectMapper();

    static OfficialVerificationMessageResolver messages() {
        return OfficialVerificationTestMessages.deterministic();
    }

    SecurityDecisionStandardPromptTemplate.StructuredPrompt productionPromptWithRagDocuments() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-pqa-extreme-production")
                .timestamp(LocalDateTime.of(2026, 6, 3, 10, 0))
                .userId("persona_fin_lead")
                .sessionId("session-pqa-extreme")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceSensitivity", "MEDIUM");
        event.addMetadata("sensitiveResource", false);
        event.addMetadata("mfaVerified", false);
        event.addMetadata("authorizationEffect", "ALLOW");

        return buildPrompt(template, event);
    }

    SecurityDecisionStandardPromptTemplate.StructuredPrompt browserEquivalentPromptWithRagDocuments() {
        return browserEquivalentPromptWithRuntimeGovernanceRules(List.of());
    }

    SecurityDecisionStandardPromptTemplate.StructuredPrompt browserEquivalentPromptWithRuntimeGovernanceRule(
            PromptRuntimeGovernanceRule rule) {
        return browserEquivalentPromptWithRuntimeGovernanceRules(List.of(rule));
    }

    private SecurityDecisionStandardPromptTemplate.StructuredPrompt browserEquivalentPromptWithRuntimeGovernanceRules(
            List<PromptRuntimeGovernanceRule> rules) {
        PromptRuntimeGovernanceRuleProvider provider = rules == null || rules.isEmpty()
                ? PromptRuntimeGovernanceRuleProvider.none()
                : context -> rules;
        PromptContextComposer promptContextComposer = rules == null || rules.isEmpty()
                ? new PromptContextComposer()
                : new PromptContextComposer(new PromptSlotRenderer(), businessLabelSlotPlanProvider());
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                promptContextComposer,
                null,
                provider);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-pqa-extreme-browser-equivalent")
                .source(SecurityEvent.EventSource.API)
                .timestamp(LocalDateTime.of(2026, 6, 3, 10, 0))
                .sourceIp("121.139.20.5")
                .userId("persona_fin_lead")
                .sessionId("session-pqa-extreme")
                .userAgent("Chrome/120")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("tenantId", "demo");
        event.addMetadata("organizationId", "demo-org");
        event.addMetadata("orgId", "demo-org");
        event.addMetadata("deviceOs", "MACOS");
        event.addMetadata("deviceBrowser", "Chrome");
        event.addMetadata("deviceLanguage", "ko-KR");
        event.addMetadata("deviceFingerprintMatch", true);
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("method", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("path", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceId", "resource-001");
        event.addMetadata("requestedResourceId", "resource-001");
        event.addMetadata("protectedResourceId", "resource-001");
        event.addMetadata("resourceType", "sensitive");
        event.addMetadata("endpointKey", "sensitive");
        event.addMetadata("currentResourceFamily", "SENSITIVE");
        event.addMetadata("resourceFamily", "SENSITIVE");
        event.addMetadata("expectedResourceFamilies", List.of("SENSITIVE"));
        event.addMetadata("allowedResourceFamilies", List.of("SENSITIVE"));
        event.addMetadata("currentActionFamily", "READ");
        event.addMetadata("actionFamily", "READ");
        event.addMetadata("expectedActionFamilies", List.of("READ"));
        event.addMetadata("allowedActionFamilies", List.of("READ"));
        event.addMetadata("recentPermissionChanges", List.of("NONE_RECORDED"));
        event.addMetadata("authMethod", "PASSWORD");
        event.addMetadata("authenticationType", "PASSWORD");
        event.addMetadata("approvalRequired", false);
        event.addMetadata("approvalGranted", false);
        event.addMetadata("approvalStatus", "NOT_APPLICABLE");
        event.addMetadata("delegated", false);
        event.addMetadata("objectiveDrift", false);
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("isSensitiveResource", true);
        event.addMetadata("businessLabel", "Sensitive Security Test Resource resource-001");
        event.addMetadata("mfaVerified", false);
        event.addMetadata("failedLoginAttempts", 0);
        event.addMetadata("isNewDevice", false);
        event.addMetadata("isNewSession", false);
        event.addMetadata("isNewUser", false);
        event.addMetadata("intentBotUserAgent", false);
        event.addMetadata("intentMissingReferer", false);
        event.addMetadata("authorizationEffect", "ALLOW");
        event.addMetadata("sessionNarrativeSummary",
                "Session age 1m | Previous path /admin/api/security-test/normal/resource-001 | Recent actions READ");
        event.addMetadata("sessionAgeMinutes", 1);
        event.addMetadata("previousPath", "/admin/api/security-test/normal/resource-001");
        event.addMetadata("previousActionFamily", "READ");
        event.addMetadata("lastRequestIntervalMs", 12000L);
        event.addMetadata("sessionActionSequence", List.of("READ"));
        event.addMetadata("sessionProtectableSequence", List.of("/admin/api/security-test/sensitive/resource-001"));

        return buildPrompt(template, event);
    }

    private PromptSlotPlanProvider businessLabelSlotPlanProvider() {
        PromptSlotPlan businessLabelPlan = new PromptSlotPlan(
                "BusinessLabel",
                "RESOURCE_AND_ACTION",
                "BusinessLabel",
                "resource.businessLabel",
                "PromptContextComposer",
                "P1_HIGH_VALUE",
                "PROTECT");
        return new PromptSlotPlanProvider() {
            @Override
            public PromptSlotPlan planFor(String sectionKey, String labelKey) {
                return PromptSlotPlan.unscoped(sectionKey, labelKey);
            }

            @Override
            public List<PromptSlotPlan> plansForSlotKey(String promptKey, String slotKey) {
                return "cortex.security-decision".equals(promptKey)
                        && businessLabelPlan.slotKey().equals(slotKey)
                        ? List.of(businessLabelPlan)
                        : List.of();
            }
        };
    }

    String appendConflictingResourceSection(String userPrompt) {
        return userPrompt + """

                === RESOURCE AND ACTION CONTEXT ===
                ResourceId: resource-001
                RequestPath: /admin/api/security-test/sensitive/other-resource
                HttpMethod: GET
                ActionFamily: READ
                Sensitivity: MEDIUM
                SensitiveResource: false
                """;
    }

    SealedEvidencePackage packageFor(String systemPrompt, String userPrompt, String ragResultsJson) {
        return SealedEvidencePackage.builder()
                .packageId("pkg-pqa-extreme-production")
                .correlationId("corr-pqa-extreme-production")
                .tenantId("demo")
                .userId("persona_fin_lead")
                .systemPromptText(systemPrompt)
                .userPromptText(userPrompt)
                .rawSystemPrompt(systemPrompt)
                .rawUserPrompt(userPrompt)
                .systemPromptHash(prefixedSha256(systemPrompt))
                .userPromptHash(prefixedSha256(userPrompt))
                .rawSystemPromptHash(prefixedSha256(systemPrompt))
                .rawUserPromptHash(prefixedSha256(userPrompt))
                .promptHash(prefixedSha256(systemPrompt + "\n" + userPrompt))
                .promptEvidenceManifestJson("{\"fields\":[\"RAG EVIDENCE\",\"RESOURCE AND ACTION CONTEXT\"]}")
                .promptExecutionMetadataJson("""
                        {
                          "userPromptHash": "%s",
                          "systemPromptHash": "%s",
                          "rawUserPromptHash": "%s",
                          "rawSystemPromptHash": "%s",
                          "promptSectionSet": ["CURRENT REQUEST AND EVENT", "RESOURCE AND ACTION CONTEXT", "RAG EVIDENCE"]
                        }
                        """.formatted(
                        prefixedSha256(userPrompt),
                        prefixedSha256(systemPrompt),
                        prefixedSha256(userPrompt),
                        prefixedSha256(systemPrompt)))
                .requestFactsJson("{}")
                .authStateJson("{}")
                .ragResultsJson(ragResultsJson)
                .decisionJson("{}")
                .packageHash("sha256:test")
                .build();
    }

    SealedEvidencePackage packageFor(
            SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt,
            String userPrompt,
            String ragResultsJson) {
        String effectiveUserPrompt = userPrompt != null ? userPrompt : prompt.userText();
        String systemPrompt = prompt.systemText();
        return SealedEvidencePackage.builder()
                .packageId("pkg-pqa-extreme-production")
                .correlationId("corr-pqa-extreme-production")
                .tenantId("demo")
                .userId("persona_fin_lead")
                .systemPromptText(systemPrompt)
                .userPromptText(effectiveUserPrompt)
                .rawSystemPrompt(systemPrompt)
                .rawUserPrompt(effectiveUserPrompt)
                .systemPromptHash(prefixedSha256(systemPrompt))
                .userPromptHash(prefixedSha256(effectiveUserPrompt))
                .rawSystemPromptHash(prefixedSha256(systemPrompt))
                .rawUserPromptHash(prefixedSha256(effectiveUserPrompt))
                .promptHash(prefixedSha256(systemPrompt + "\n" + effectiveUserPrompt))
                .promptEvidenceManifestJson(
                        "{\"fields\":[\"CURRENT REQUEST AND EVENT\",\"RESOURCE AND ACTION CONTEXT\",\"RAG EVIDENCE\"]}")
                .promptExecutionMetadataJson(metadataJson(prompt.executionMetadata(), systemPrompt, effectiveUserPrompt))
                .requestFactsJson("""
                        {
                          "resourceId": "resource-001",
                          "requestPath": "/admin/api/security-test/sensitive/resource-001",
                          "httpMethod": "GET",
                          "resourceSensitivity": "HIGH",
                          "isSensitiveResource": true
                        }
                        """)
                .authStateJson("{\"authorizationEffect\":\"ALLOW\"}")
                .ragResultsJson(ragResultsJson)
                .decisionJson("{}")
                .packageHash("sha256:test")
                .build();
    }

    String ragAvailableJson() {
        return """
                {
                  "ragSearchExecuted": true,
                  "ragRetrievalState": "AVAILABLE",
                  "ragAbsenceReason": "NONE",
                  "relatedDocumentCount": 2,
                  "ragCandidateDocumentCount": 2,
                  "ragAuthorizedDocumentCount": 2,
                  "ragDeniedDocumentCount": 0,
                  "ragPermissionFiltered": false,
                  "ragProjectedToFinalPrompt": true,
                  "ragProjectionState": "PROJECTED"
                }
                """;
    }

    private SecurityDecisionStandardPromptTemplate.StructuredPrompt buildPrompt(
            SecurityDecisionStandardPromptTemplate template,
            SecurityEvent event) {
        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext =
                new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("persona_fin_lead");
        sessionContext.setSessionId("session-pqa-extreme");
        sessionContext.setAuthMethod("PASSWORD");
        sessionContext.setRequestCount(3);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(personalBaselineEvidence());
        behaviorAnalysis.setPersonalBaselineAvailable(true);
        behaviorAnalysis.setPersonalBaselineEstablished(false);

        return template.buildStructuredPrompt(event, sessionContext, behaviorAnalysis, ragDocuments());
    }

    private List<Document> ragDocuments() {
        return List.of(
                new Document(
                        "User accessed /admin/api/security-test/sensitive/resource-001 via GET from managed browser.",
                        ragMetadata()),
                new Document(
                        "User repeated access to /admin/api/security-test/sensitive/resource-001 via GET from managed browser.",
                        ragMetadata()));
    }

    private Map<String, Object> ragMetadata() {
        return Map.of(
                VectorDocumentMetadata.DOCUMENT_TYPE, "behavior",
                VectorDocumentMetadata.USER_ID, "persona_fin_lead",
                VectorDocumentMetadata.TENANT_ID, "demo",
                VectorDocumentMetadata.ORGANIZATION_ID, "demo-org",
                VectorDocumentMetadata.AUTHORIZATION_DECISION, "ALLOWED_USER_SCOPE",
                VectorDocumentMetadata.ACCESS_SCOPE, "USER",
                VectorDocumentMetadata.PURPOSE_MATCH, true,
                VectorDocumentMetadata.RETRIEVAL_PURPOSE, "security_investigation",
                VectorDocumentMetadata.RETRIEVAL_POLICY_SUMMARY,
                "purpose=security_investigation,user=persona_fin_lead,organization=demo-org,tenant=demo,types=*",
                VectorDocumentMetadata.PROVENANCE_SUMMARY, "Security decision memory from runtime event");
    }

    private BaselineEvidenceSnapshot personalBaselineEvidence() {
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                true,
                false,
                19L,
                0.82d,
                List.of("10.10.0", "211.234.5"),
                List.of("10", "11", "13"),
                List.of("1", "2", "3"),
                List.of("Chrome/120"),
                List.of("MACOS"),
                List.of("/admin/api/security-test/sensitive/*"),
                List.of("PASSWORD"),
                List.of("READ"),
                List.of("sensitive"),
                "personal baseline provisional | observations=19",
                BaselineEvidenceStatus.AVAILABLE,
                "personal baseline provisional | observations=19");
    }

    private String prefixedSha256(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(hash);
        }
        catch (Exception ex) {
            throw new IllegalStateException("Unable to hash prompt", ex);
        }
    }

    private String metadataJson(
            PromptExecutionMetadata metadata,
            String systemPrompt,
            String userPrompt) {
        try {
            Map<String, Object> source = metadata == null ? Map.of() : metadata.toMetadataMap();
            Map<String, Object> values = new LinkedHashMap<>(source);
            values.put("systemPromptHash", prefixedSha256(systemPrompt));
            values.put("userPromptHash", prefixedSha256(userPrompt));
            values.put("rawSystemPromptHash", prefixedSha256(systemPrompt));
            values.put("rawUserPromptHash", prefixedSha256(userPrompt));
            values.put("promptHash", prefixedSha256(systemPrompt + "\n" + userPrompt));
            values.putIfAbsent("contractVersion", "final-user-prompt.v1");
            values.putIfAbsent("packageId", "pkg-pqa-extreme-production");
            return objectMapper.writeValueAsString(values);
        }
        catch (Exception exception) {
            throw new IllegalStateException("Unable to serialize prompt execution metadata", exception);
        }
    }
}
