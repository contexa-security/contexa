package io.contexa.contexacore.autonomous.context;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CanonicalSecurityContext {

    private Actor actor;

    private Session session;

    private Resource resource;

    private Authorization authorization;

    private Delegation delegation;

    private Bridge bridge;

    private ObservedScope observedScope;

    private SessionNarrativeProfile sessionNarrativeProfile;

    private WorkProfile workProfile;

    private RoleScopeProfile roleScopeProfile;

    private PeerCohortProfile peerCohortProfile;

    private FrictionProfile frictionProfile;

    private ReasoningMemoryProfile reasoningMemoryProfile;

    private ContextCoverageReport coverage;

    @Builder.Default
    private Map<String, Object> attributes = new LinkedHashMap<>();

    @Builder.Default
    private Instant collectedAt = Instant.now();

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Actor {
        private String userId;
        private String externalSubjectId;
        private String organizationId;
        private String tenantId;
        private String department;
        private String position;
        private String principalType;
        private String bridgeSubjectKey;
        @Builder.Default
        private List<String> roleSet = new ArrayList<>();
        @Builder.Default
        private List<String> authoritySet = new ArrayList<>();
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Session {
        private String sessionId;
        private String clientIp;
        private String userAgent;
        private String authenticationType;
        private String authenticationAssurance;
        private Boolean mfaVerified;
        private Integer recentMfaFailureCount;
        private String lastMfaUsedAt;
        private Integer failedLoginAttempts;
        private Integer recentRequestCount;
        private Integer recentChallengeCount;
        private Integer recentBlockCount;
        private Integer recentEscalationCount;
        private Boolean blockedUser;
        private Boolean newSession;
        private Boolean newUser;
        private Boolean newDevice;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Resource {
        private String resourceId;
        private String resourceType;
        private String businessLabel;
        private String sensitivity;
        private String requestPath;
        private String httpMethod;
        private String actionFamily;
        private Boolean sensitiveResource;
        private Boolean privileged;
        private Boolean exportSensitive;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Authorization {
        @Builder.Default
        private List<String> effectiveRoles = new ArrayList<>();
        @Builder.Default
        private List<String> effectivePermissions = new ArrayList<>();
        @Builder.Default
        private List<String> scopeTags = new ArrayList<>();
        private String authorizationEffect;
        private String policyId;
        private String policyVersion;
        private Boolean privileged;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Delegation {
        private Boolean delegated;
        private String agentId;
        private String objectiveId;
        private String objectiveFamily;
        private String objectiveSummary;
        @Builder.Default
        private List<String> allowedOperations = new ArrayList<>();
        @Builder.Default
        private List<String> allowedResources = new ArrayList<>();
        private Boolean approvalRequired;
        private Boolean privilegedExportAllowed;
        private Boolean containmentOnly;
        private Boolean objectiveDrift;
        private String objectiveDriftSummary;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Bridge {
        private String coverageLevel;
        private Integer coverageScore;
        @Builder.Default
        private List<String> missingContexts = new ArrayList<>();
        private String summary;
        @Builder.Default
        private List<String> remediationHints = new ArrayList<>();
        private String authenticationSource;
        private String authorizationSource;
        private String delegationSource;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ObservedScope {
        private String profileSource;
        private String summary;
        private Integer recentProtectableAccessCount;
        private Integer recentDeniedAccessCount;
        private Integer recentSensitiveAccessCount;
        @Builder.Default
        private List<String> frequentResources = new ArrayList<>();
        @Builder.Default
        private List<String> frequentActionFamilies = new ArrayList<>();
        private Boolean rareCurrentResource;
        private Boolean rareCurrentActionFamily;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SessionNarrativeProfile {
        private String summary;
        private Integer sessionAgeMinutes;
        private String previousPath;
        private String previousActionFamily;
        private Long lastRequestIntervalMs;
        @Builder.Default
        private List<String> sessionActionSequence = new ArrayList<>();
        @Builder.Default
        private List<String> sessionProtectableSequence = new ArrayList<>();
        private Boolean burstPattern;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class WorkProfile {
        private String summary;
        @Builder.Default
        private List<String> frequentProtectableResources = new ArrayList<>();
        @Builder.Default
        private List<String> frequentActionFamilies = new ArrayList<>();
        @Builder.Default
        private List<String> frequentSensitiveResourceCategories = new ArrayList<>();
        @Builder.Default
        private List<String> protectableResourceHeatmap = new ArrayList<>();
        @Builder.Default
        private List<Integer> normalAccessHours = new ArrayList<>();
        @Builder.Default
        private List<Integer> normalAccessDays = new ArrayList<>();
        private Double normalRequestRate;
        private Integer normalSessionLengthMinutes;
        private String normalReadWriteExportRatio;
        private Double normalPrivilegedActionFrequency;
        private Double protectableInvocationDensity;
        private String seasonalBusinessProfile;
        @Builder.Default
        private List<String> longTailLegitimateTasks = new ArrayList<>();
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RoleScopeProfile {
        private String summary;
        private String currentResourceFamily;
        private String currentActionFamily;
        @Builder.Default
        private List<String> expectedResourceFamilies = new ArrayList<>();
        @Builder.Default
        private List<String> expectedActionFamilies = new ArrayList<>();
        @Builder.Default
        private List<String> forbiddenResourceFamilies = new ArrayList<>();
        @Builder.Default
        private List<String> forbiddenActionFamilies = new ArrayList<>();
        @Builder.Default
        private List<String> normalApprovalPatterns = new ArrayList<>();
        @Builder.Default
        private List<String> normalEscalationPatterns = new ArrayList<>();
        @Builder.Default
        private List<String> recentPermissionChanges = new ArrayList<>();
        private Boolean resourceFamilyDrift;
        private Boolean actionFamilyDrift;
        private Boolean temporaryElevation;
        private String temporaryElevationReason;
        private Boolean elevatedPrivilegeWindowActive;
        private String elevationWindowSummary;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PeerCohortProfile {
        private String cohortId;
        private String summary;
        @Builder.Default
        private List<String> preferredResources = new ArrayList<>();
        @Builder.Default
        private List<String> preferredActionFamilies = new ArrayList<>();
        private String normalProtectableFrequencyBand;
        private String normalSensitivityBand;
        private Boolean outlierAgainstCohort;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FrictionProfile {
        private String summary;
        private Integer recentChallengeCount;
        private Integer recentBlockCount;
        private Integer recentEscalationCount;
        private Boolean approvalRequired;
        private Boolean approvalGranted;
        private Boolean approvalMissing;
        private String approvalStatus;
        @Builder.Default
        private List<String> approvalLineage = new ArrayList<>();
        @Builder.Default
        private List<String> pendingApproverRoles = new ArrayList<>();
        private String approvalTicketId;
        private Integer approvalDecisionAgeMinutes;
        private Boolean breakGlass;
        private Integer recentDeniedAccessCount;
        private Boolean blockedUser;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ReasoningMemoryProfile {
        private String summary;
        private Long reinforcedCaseCount;
        private Long hardNegativeCaseCount;
        private Long falseNegativeCaseCount;
        private Long knowledgeAssistedCaseCount;
        private String objectiveAwareReasoningMemory;
        private String retentionTier;
        private String recallPriority;
        private String freshnessState;
        private String reasoningState;
        private String cohortPreference;
        private String memoryRiskProfile;
        private Integer retrievalWeight;
        @Builder.Default
        private List<String> matchedSignalKeys = new ArrayList<>();
        @Builder.Default
        private List<String> objectiveFamilies = new ArrayList<>();
        @Builder.Default
        private List<String> memoryGuardrails = new ArrayList<>();
        @Builder.Default
        private List<String> xaiLinkedFacts = new ArrayList<>();
        @Builder.Default
        private List<String> reasoningFacts = new ArrayList<>();
        private String crossTenantObjectiveMisusePackSummary;
        @Builder.Default
        private List<String> crossTenantObjectiveMisuseFacts = new ArrayList<>();
    }
}
