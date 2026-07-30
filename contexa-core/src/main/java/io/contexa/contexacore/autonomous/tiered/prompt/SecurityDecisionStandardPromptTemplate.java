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

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleProvider;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyRuntimePack;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackSnapshot;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.*;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import lombok.Getter;
import lombok.Setter;
import org.springframework.ai.document.Document;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SecurityDecisionStandardPromptTemplate extends AbstractStandardPromptTemplate<SecurityDecisionResponseLite> {

    private static final String STRUCTURED_PROMPT_CACHE_KEY = "securityDecisionStructuredPrompt";

    public static final String STANDARD_TEMPLATE_KEY = "SecurityDecisionStandard";
    public static final PromptGovernanceDescriptor SECURITY_DECISION_PROMPT_GOVERNANCE =
            new PromptGovernanceDescriptor(
                    "cortex.security-decision",
                    STANDARD_TEMPLATE_KEY,
                    "2026.07.30-v19",
                    "CORTEX_PROMPT_CONTRACT_V2",
                    PromptReleaseStatus.PRODUCTION,
                    "contexa-cortex-core",
                    "P5-DECISION-INPUT-OPTIMIZATION-GATE-2026-07-30-V19",
                    "2026.07.30-phase5-v19-gpt-5-nano-decision-input-optimization-gate",
                    "2026.07.26-v5",
                    "Zero Trust runtime decision prompt v19 preserves final authorization consistency and removes repeated audit diagnostics and duplicate RAG security signatures from model input",
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
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer) {
        this(eventEnricher,
                tieredStrategyProperties,
                canonicalSecurityContextProvider,
                promptContextComposer,
                null);
    }

    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer,
            PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver) {
        this(eventEnricher,
                tieredStrategyProperties,
                canonicalSecurityContextProvider,
                promptContextComposer,
                promptGovernanceDescriptorResolver,
                PromptRuntimeGovernanceRuleProvider.none());
    }

    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer,
            PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver,
            PromptRuntimeGovernanceRuleProvider promptRuntimeGovernanceRuleProvider) {
        this(new SecurityDecisionPromptSections(
                eventEnricher,
                tieredStrategyProperties,
                canonicalSecurityContextProvider,
                promptContextComposer,
                SECURITY_DECISION_PROMPT_GOVERNANCE,
                promptGovernanceDescriptorResolver,
                promptRuntimeGovernanceRuleProvider));
    }

    public SecurityDecisionStandardPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties) {
        this(eventEnricher, tieredStrategyProperties, null, null);
    }
    public SecurityDecisionStandardPromptTemplate(SecurityDecisionPromptSections promptSections) {
        super(SecurityDecisionResponseLite.class);
        this.promptSections = promptSections;
    }

    @Override
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return buildStructuredPrompt(request).systemText();
    }

    @Override
    protected boolean shouldIncludeFormatInstructions(AIRequest<? extends DomainContext> request) {
        return resolveStructuredOutputMode(request) != StructuredOutputMode.NATIVE_STRUCTURED;
    }

    @Override
    protected String getFormatInstructions() {
        return SecurityDecisionContractSectionBuilder.formatInstructions();
    }

    @Override
    protected boolean shouldIncludeSystemMetadata(AIRequest<? extends DomainContext> request) {
        return false;
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

    @Override
    public PromptExecutionMetadata buildPromptExecutionMetadata(
            AIRequest<? extends DomainContext> request,
            String systemPrompt,
            String userPrompt) {
        StructuredPrompt structuredPrompt = buildStructuredPrompt(request);
        if (structuredPrompt.executionMetadata() != null) {
            PromptExecutionMetadata baseMetadata = structuredPrompt.executionMetadata();
            return PromptGovernanceSupport.buildExecutionMetadata(
                    baseMetadata.governanceDescriptor(),
                    baseMetadata.budgetProfile(),
                    baseMetadata.sectionSet(),
                    baseMetadata.omittedSections(),
                    baseMetadata.omissionLedger(),
                    baseMetadata.duplicationInventory(),
                    baseMetadata.promptEvidenceCompleteness(),
                    PromptGovernanceSupport.resolveRequestedModelHint(request),
                    systemPrompt,
                    userPrompt,
                    systemPrompt,
                    userPrompt,
                    baseMetadata.promptCompressionLedger(),
                    baseMetadata.supplementalMetadata());
        }
        return PromptGovernanceSupport.buildExecutionMetadata(
                getPromptGovernanceDescriptor(),
                PromptGovernanceSupport.resolveRequestedModelHint(request),
                systemPrompt,
                userPrompt);
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

    public StructuredPrompt buildStructuredPrompt(
            SecurityEvent event,
            SessionContext sessionContext,
            BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments,
            PromptBudgetProfile budgetProfile,
            StructuredOutputMode structuredOutputMode) {
        return promptSections.buildStructuredPrompt(
                event,
                sessionContext,
                behaviorAnalysis,
                relatedDocuments,
                budgetProfile,
                structuredOutputMode);
    }

    public String buildPrompt(
            SecurityEvent event,
            SessionContext sessionContext,
            BehaviorAnalysis behaviorAnalysis,
            List<Document> relatedDocuments) {
        return promptSections.buildPrompt(event, sessionContext, behaviorAnalysis, relatedDocuments);
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
        StructuredOutputMode structuredOutputMode = resolveStructuredOutputMode(securityDecisionRequest);
        StructuredPrompt structuredPrompt = buildStructuredPrompt(
                context.getSecurityEvent(),
                context.getSessionContext(),
                context.getBehaviorAnalysis(),
                context.getRelatedDocuments(),
                budgetProfile,
                structuredOutputMode
        );
        request.withParameter(STRUCTURED_PROMPT_CACHE_KEY, structuredPrompt);
        return structuredPrompt;
    }

    private StructuredOutputMode resolveStructuredOutputMode(AIRequest<? extends DomainContext> request) {
        if (request == null) {
            return StructuredOutputMode.VALIDATED_CONVERTER;
        }
        return StructuredOutputMode.fromValue(
                request.getParameter("structuredOutputMode", Object.class),
                StructuredOutputMode.VALIDATED_CONVERTER);
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
        private boolean baselineEstablished;
        private List<ThreatIntelligenceSnapshot.ThreatSignalItem> activeThreatSignals = List.of();
        private ThreatIntelligenceMatchContext threatIntelligenceMatchContext;
        private ThreatKnowledgePackSnapshot threatKnowledgePack;
        private ThreatKnowledgePackMatchContext threatKnowledgePackMatchContext;
        private DetectionStrategyPackSnapshot detectionStrategyPack;
        private DetectionStrategyRuntimePack detectionStrategyRuntimePack;
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
        private String[] baselineBrowsers;
        private String[] baselineIpBands;
        private String[] baselineAuthenticationTypes;
        private String[] baselineActionFamilies;
        private String[] baselineResourceFamilies;
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
        private double cohortSeedWeight;
        private String cohortSeedWeightState;
        private List<String> cohortSeedPolicyFacts = List.of();
        private BaselineEvidenceSnapshot personalBaselineEvidence;
        private BaselineEvidenceSnapshot supportingBaselineEvidence;
        private LearningContextEvidence learningContextEvidence;

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

        public DetectionStrategyPackSnapshot getDetectionStrategyPack() {
            return detectionStrategyPack;
        }

        public DetectionStrategyRuntimePack getDetectionStrategyRuntimePack() {
            return detectionStrategyRuntimePack;
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

        public String[] getBaselineBrowsers() {
            return baselineBrowsers;
        }

        public String[] getBaselineIpBands() {
            return baselineIpBands;
        }

        public String[] getBaselineAuthenticationTypes() {
            return baselineAuthenticationTypes;
        }

        public String[] getBaselineActionFamilies() {
            return baselineActionFamilies;
        }

        public String[] getBaselineResourceFamilies() {
            return baselineResourceFamilies;
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

        public double getCohortSeedWeight() {
            return cohortSeedWeight;
        }

        public String getCohortSeedWeightState() {
            return cohortSeedWeightState;
        }

        public List<String> getCohortSeedPolicyFacts() {
            return cohortSeedPolicyFacts != null ? cohortSeedPolicyFacts : List.of();
        }

        public BaselineEvidenceSnapshot getPersonalBaselineEvidence() {
            return personalBaselineEvidence;
        }

        public BaselineEvidenceSnapshot getSupportingBaselineEvidence() {
            return supportingBaselineEvidence;
        }

        public LearningContextEvidence getLearningContextEvidence() {
            return learningContextEvidence;
        }
    }
}
