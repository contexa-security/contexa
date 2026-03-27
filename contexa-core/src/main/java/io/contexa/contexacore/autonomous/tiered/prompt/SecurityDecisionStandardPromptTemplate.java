package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.PromptContextComposer;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.mcp.McpSecurityContextProvider;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackSnapshot;
import io.contexa.contexacore.autonomous.tiered.template.SecurityDecisionPromptSections;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.AbstractStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import lombok.Getter;
import lombok.Setter;
import org.springframework.ai.document.Document;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class SecurityDecisionStandardPromptTemplate extends AbstractStandardPromptTemplate<SecurityDecisionResponse> {

    private static final String STRUCTURED_PROMPT_CACHE_KEY = "securityDecisionStructuredPrompt";

    public static final String STANDARD_TEMPLATE_KEY = "SecurityDecisionStandard";
    public static final PromptGovernanceDescriptor SECURITY_DECISION_PROMPT_GOVERNANCE =
            new PromptGovernanceDescriptor(
                    "cortex.security-decision",
                    STANDARD_TEMPLATE_KEY,
                    "2026.03.26-e0.1",
                    "CORTEX_PROMPT_CONTRACT_V2",
                    PromptReleaseStatus.PRODUCTION,
                    "contexa-cortex-core",
                    "P0-Preflight/E0-1",
                    "CORTEX_NIST_ISO_ALIGNMENT_BASELINE.md",
                    "2026.03.17-pre-governance",
                    "NIST/ISO aligned governed security decision prompt with standardized runtime implementation",
                    List.of(
                            "STRICT_JSON_SCHEMA",
                            "LOW_TEMPERATURE_SECURITY_DECISION",
                            "EVIDENCE_ONLY_RETRIEVAL",
                            "MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI"
                    ),
                    SecurityDecisionStandardPromptTemplate.class.getName());

    private final SecurityDecisionPromptSections promptSections;

    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            McpSecurityContextProvider mcpSecurityContextProvider,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer) {
        this(new SecurityDecisionPromptSections(
                eventEnricher,
                tieredStrategyProperties,
                mcpSecurityContextProvider,
                canonicalSecurityContextProvider,
                promptContextComposer,
                SECURITY_DECISION_PROMPT_GOVERNANCE));
    }

    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties) {
        this(eventEnricher, tieredStrategyProperties, null, null, null);
    }

    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            McpSecurityContextProvider mcpSecurityContextProvider) {
        this(eventEnricher, tieredStrategyProperties, mcpSecurityContextProvider, null, null);
    }

    public SecurityDecisionStandardPromptTemplate(SecurityDecisionPromptSections promptSections) {
        super(SecurityDecisionResponse.class);
        this.promptSections = promptSections;
    }

    @Override
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return buildStructuredPrompt(request).systemText();
    }

    @Override
    public TemplateType getSupportedType() {
        return SecurityDecisionRequest.TEMPLATE_TYPE;
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        return buildStructuredPrompt(request).userText();
    }

    @Override
    public PromptGovernanceDescriptor getPromptGovernanceDescriptor() {
        return SECURITY_DECISION_PROMPT_GOVERNANCE;
    }

    public StructuredPrompt buildStructuredPrompt(
            SecurityEvent event,
            SessionContext sessionContext,
            BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments) {
        return promptSections.buildStructuredPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments);
    }

    public StructuredPrompt buildStructuredPrompt(
            SecurityEvent event,
            SessionContext sessionContext,
            BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments,
            PromptBudgetProfile budgetProfile) {
        return promptSections.buildStructuredPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments, budgetProfile);
    }

    public String buildPrompt(
            SecurityEvent event,
            SessionContext sessionContext,
            BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments) {
        return promptSections.buildPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments);
    }

    public Optional<CanonicalSecurityContext> resolveCanonicalSecurityContextForGuardrail(SecurityEvent event) {
        return promptSections.resolveCanonicalSecurityContextForGuardrail(event);
    }

    private StructuredPrompt buildStructuredPrompt(AIRequest<? extends DomainContext> request) {
        StructuredPrompt cached = request.getParameter(STRUCTURED_PROMPT_CACHE_KEY, StructuredPrompt.class);
        if (cached != null) {
            return cached;
        }

        if (!(request instanceof SecurityDecisionRequest securityDecisionRequest)) {
            throw new IllegalArgumentException("SecurityDecisionStandardPromptTemplate supports only SecurityDecisionRequest");
        }

        SecurityDecisionContext context = securityDecisionRequest.getContext();
        PromptBudgetProfile budgetProfile = PromptBudgetProfile.fromKey(
                securityDecisionRequest.getParameter("promptBudgetProfile", String.class),
                null);
        StructuredPrompt structuredPrompt = buildStructuredPrompt(
                context.getSecurityEvent(),
                context.getSessionContext(),
                context.getBehaviorAnalysis(),
                context.getRelatedDocuments(),
                budgetProfile
        );
        request.withParameter(STRUCTURED_PROMPT_CACHE_KEY, structuredPrompt);
        return structuredPrompt;
    }

    public record StructuredPrompt(
            String systemText,
            String userText,
            PromptExecutionMetadata executionMetadata) {

        public StructuredPrompt(String systemText, String userText) {
            this(systemText, userText, null);
        }
    }

    public static class DetectedPatterns {
        public final Set<String> osSet = new HashSet<>();
        public final Set<String> ipSet = new HashSet<>();
        public final Set<String> hourSet = new HashSet<>();
        public final Set<String> daySet = new HashSet<>();
        public final Set<String> uaSet = new HashSet<>();
        public final Set<String> pathSet = new HashSet<>();
        public String relatedContext;
        public boolean hasRelatedDocs;
    }

    @Getter
    @Setter
    public static class SessionContext {
        private String sessionId;
        private String userId;
        private String authMethod;
        private List<String> recentActions = List.of();
        private Integer sessionAgeMinutes;
        private Integer requestCount;

        public List<String> getRecentActions() {
            return recentActions != null ? recentActions : List.of();
        }
    }

    @Setter
    public static class BehaviorAnalysis {
        private List<String> similarEvents = List.of();
        private String baselineContext;
        private boolean baselineEstablished;
        private List<ThreatIntelligenceSnapshot.ThreatSignalItem> activeThreatSignals = List.of();
        private ThreatIntelligenceMatchContext threatIntelligenceMatchContext;
        private ThreatKnowledgePackSnapshot threatKnowledgePack;
        private ThreatKnowledgePackMatchContext threatKnowledgePackMatchContext;
        private Boolean isNewSession;
        private Boolean isNewDevice;
        private String previousUserAgentOS;
        private String currentUserAgentOS;
        private String[] baselineIpRanges;
        private String[] baselineOperatingSystems;
        private String[] baselineUserAgents;
        private String[] baselineFrequentPaths;
        private Integer[] baselineAccessHours;
        private Integer[] baselineAccessDays;
        private Long baselineUpdateCount;
        private Double baselineAvgTrustScore;
        private String previousUserAgentBrowser;
        private String currentUserAgentBrowser;
        private Long lastRequestIntervalMs;
        private String previousPath;
        private Boolean contextBindingHashMismatch;
        private Double baselineAvgRequestRate;
        private boolean personalBaselineAvailable;
        private boolean personalBaselineEstablished;
        private boolean organizationBaselineAvailable;
        private boolean organizationBaselineEstablished;
        private boolean cohortSeedRecommended;
        private boolean cohortSeedApplied;
        private List<String> cohortSeedSupportingDimensions = List.of();
        private BaselineSeedSnapshot cohortBaselineSeed;

        public List<String> getSimilarEvents() {
            return similarEvents != null ? similarEvents : List.of();
        }

        public String getBaselineContext() {
            return baselineContext;
        }

        public boolean isBaselineEstablished() {
            return baselineEstablished;
        }

        public List<ThreatIntelligenceSnapshot.ThreatSignalItem> getActiveThreatSignals() {
            return activeThreatSignals != null ? activeThreatSignals : List.of();
        }

        public ThreatIntelligenceMatchContext getThreatIntelligenceMatchContext() {
            return threatIntelligenceMatchContext;
        }

        public ThreatKnowledgePackSnapshot getThreatKnowledgePack() {
            return threatKnowledgePack;
        }

        public ThreatKnowledgePackMatchContext getThreatKnowledgePackMatchContext() {
            return threatKnowledgePackMatchContext;
        }

        public Boolean getIsNewSession() {
            return isNewSession;
        }

        public Boolean getIsNewDevice() {
            return isNewDevice;
        }

        public String getPreviousUserAgentOS() {
            return previousUserAgentOS;
        }

        public String getCurrentUserAgentOS() {
            return currentUserAgentOS;
        }

        public String[] getBaselineIpRanges() {
            return baselineIpRanges;
        }

        public String[] getBaselineOperatingSystems() {
            return baselineOperatingSystems;
        }

        public String[] getBaselineUserAgents() {
            return baselineUserAgents;
        }

        public String[] getBaselineFrequentPaths() {
            return baselineFrequentPaths;
        }

        public Integer[] getBaselineAccessHours() {
            return baselineAccessHours;
        }

        public Integer[] getBaselineAccessDays() {
            return baselineAccessDays;
        }

        public Long getBaselineUpdateCount() {
            return baselineUpdateCount;
        }

        public Double getBaselineAvgTrustScore() {
            return baselineAvgTrustScore;
        }

        public String getPreviousUserAgentBrowser() {
            return previousUserAgentBrowser;
        }

        public String getCurrentUserAgentBrowser() {
            return currentUserAgentBrowser;
        }

        public Long getLastRequestIntervalMs() {
            return lastRequestIntervalMs;
        }

        public String getPreviousPath() {
            return previousPath;
        }

        public Boolean getContextBindingHashMismatch() {
            return contextBindingHashMismatch;
        }

        public Double getBaselineAvgRequestRate() {
            return baselineAvgRequestRate;
        }

        public boolean isPersonalBaselineAvailable() {
            return personalBaselineAvailable;
        }

        public boolean isPersonalBaselineEstablished() {
            return personalBaselineEstablished;
        }

        public boolean isOrganizationBaselineAvailable() {
            return organizationBaselineAvailable;
        }

        public boolean isOrganizationBaselineEstablished() {
            return organizationBaselineEstablished;
        }

        public boolean isCohortSeedRecommended() {
            return cohortSeedRecommended;
        }

        public boolean isCohortSeedApplied() {
            return cohortSeedApplied;
        }

        public List<String> getCohortSeedSupportingDimensions() {
            return cohortSeedSupportingDimensions != null ? cohortSeedSupportingDimensions : List.of();
        }

        public BaselineSeedSnapshot getCohortBaselineSeed() {
            return cohortBaselineSeed;
        }
    }
}
