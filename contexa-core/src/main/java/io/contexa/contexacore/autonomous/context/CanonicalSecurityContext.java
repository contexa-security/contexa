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
package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;
import io.contexa.contexacore.autonomous.execution.ExecutionEnvelope;
import io.contexa.contexacore.autonomous.execution.ExecutionSubject;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
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

    private Device device;

    private Intent intent;

    private Location location;

    private Resource resource;

    private Authorization authorization;

    private Delegation delegation;

    private ExecutionSubject executionSubject;

    private ExecutionEnvelope executionEnvelope;

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
    private List<ContextTrustProfile> contextTrustProfiles = new ArrayList<>();

    /** Facts whose sources disagree: aliases of a field, authorization evidence, the handoff and resolved principal. */
    @Builder.Default
    private List<DataConflict> dataConflicts = new ArrayList<>();

    @Builder.Default
    private Instant collectedAt = Instant.now();

    /** When the request was observed, on the event clock (W2-5); the request-time facts are computed against it. */
    private Instant requestObservedAt;

    /** The facts the engine computed for the decision (W2-5), set when the decision prompt is built. */
    private DecisionFacts decisionFacts;

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
        /** When the signed-in account was created, from the user store; carried for the subject's account age. */
        private String accountCreatedAt;
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
        /** When the login of this session was completed (ISO-8601), as the host recorded it. */
        private String authenticationTime;
        private Boolean mfaVerified;
        private Integer recentMfaFailureCount;
        private String lastMfaUsedAt;
        /** When this session passed a Zero Trust challenge (ISO-8601); a login MFA is not a challenge. */
        private String challengeVerifiedAt;
        /** When the user last completed MFA in some session while this session has none of its own (ISO-8601). */
        private String recentMfaElsewhereAt;
        private Integer failedLoginAttempts;
        /** The window in minutes the failed logins were counted in, when the core counted them (W3-12). */
        private Integer failedLoginWindowMinutes;
        private Integer recentRequestCount;
        private Integer recentChallengeCount;
        private Integer recentBlockCount;
        private Integer recentEscalationCount;
        private Boolean blockedUser;
        private Boolean newSession;
        private Boolean newUser;
        private Boolean newDevice;
        private Integer currentAccessHour;
        private Integer concurrentSessions;
        private Integer passwordAgeDays;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Device {
        private String os;
        private String osVersion;
        private String browser;
        private String browserVersion;
        private String screenResolution;
        private String language;
        private Boolean fingerprintMatch;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Intent {
        private Boolean botUserAgent;
        private Boolean missingReferer;
        private Boolean languageMismatch;
        private Boolean tlsFingerprintAltered;
        private Boolean abnormalHeaderOrder;
        private Boolean impossibleTravel;
        private String anomalySignal;
        private String anomalySignalSource;
        /** Text a requester sent as an anomaly signal without the server-issued capability: a claim, never a signal. */
        private String untrustedAnomalySignalClaim;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Location {
        private String country;
        private String city;
        private String ipBand;
        private String asn;
        /** What kind of network the request comes from, as the host declares it ({@code NetworkZone}). */
        private String networkZone;
        /** The move the host measured since the user's previous location; null when it states none (W2-13). */
        private Movement movement;
    }

    /**
     * The host's facts about where the request comes from and how far that is from the previous location: the facts an
     * impossible-travel judgement rests on, beside the host's own yes or no (W2-13, S-9).
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Movement {
        private Double latitude;
        private Double longitude;
        private Integer distanceKm;
        private Integer elapsedMinutes;
        private String previousLocation;
        /** How sure the host is of the location baseline the move is measured from, 0 to 1. */
        private Double baselineConfidence;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Resource {
        private String resourceId;
        private String resourceType;
        /** What the host's records say the resource is (business facts, not the author's own words). */
        private String businessLabel;
        /** Text the resource's author wrote, as the host stored it: untrusted, never an instruction (W2-6). */
        private String authorText;
        /** How many items the request asks for, as the host counted them (W2-6). */
        private Integer requestedItems;
        private String sensitivity;
        /**
         * The resource class, its sensitivity grade in one vocabulary (CRITICAL, SENSITIVE, NORMAL, PUBLIC), from the
         * classification values only (sensitivity, then type). Never a business category (W2-10).
         */
        private String resourceClass;
        /**
         * What kind of business resource it is (REPORT, AUDIT_LOG, PROJECT_DOCUMENTS), as the host names it. Never a
         * class: the role scope and the delegated scope are compared in this vocabulary (W2-10).
         */
        private String resourceCategory;
        private String requestPath;
        /** The URL template the host matched, else the request path with its identifiers generalized. */
        private String pathFamily;
        private String httpMethod;
        private String actionFamily;
        /** Which source decided the action family and its grade, {@code <grade>:<metadata key>}. */
        private String actionFamilySource;
        private Boolean sensitiveResource;
        private Boolean verificationRequired;
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
        /** Whether the protected method ran: NOT_RUN (decided before it ran), COMPLETED or FAILED. */
        private String methodExecutionOutcome;
        /** The simple name of the exception a method that ran after authorization ended with; a business result. */
        private String methodExecutionFailure;
        /** When the authorization that let the request through was decided (an instant). */
        private String decisionTime;
        /** Authority names that only suggest privilege: a heuristic hint, not a granted privilege. */
        @Builder.Default
        private List<String> privilegedAuthoritySignals = new ArrayList<>();
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
        /** When the delegation ends (an instant). */
        private String expiresAt;
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
        /**
         * How each bridged fact was established, by fact (authenticationTime, mfaCompleted, authorization, ...):
         * EXPLICIT_CUSTOMER_SIGNAL, DERIVED_RUNTIME_FALLBACK, CLASS_NAME_FALLBACK, HEURISTIC_HINT_ONLY or UNAVAILABLE.
         */
        @Builder.Default
        private Map<String, String> evidenceStates = new LinkedHashMap<>();
    }

    /** One fact whose sources gave different values, with the value the context uses and how it was settled. */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DataConflict {
        /** The canonical field, such as session.mfaVerified or authorization.authorizationEffect. */
        private String field;
        /** Each source and the value it gave. */
        @Builder.Default
        private Map<String, String> sources = new LinkedHashMap<>();
        private String selected;
        /** The rule that settled the disagreement, when one did (DENY_FAIL_SAFE). */
        private String resolution;
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
        /** What the session age counts from: LOGIN, SESSION_CREATED or FIRST_ANALYSED_REQUEST. */
        private String sessionAgeBasis;
        private String previousPath;
        private String previousActionFamily;
        private Long lastRequestIntervalMs;
        @Builder.Default
        private List<String> sessionActionSequence = new ArrayList<>();
        @Builder.Default
        private List<String> sessionProtectableSequence = new ArrayList<>();
        private Boolean burstPattern;
        /** The session's most recent decisions, oldest first: "observed time | request | action family | outcome". */
        @Builder.Default
        private List<String> sessionDecisionHistory = new ArrayList<>();
        /** The same decisions as records, with their targets and item counts (W2-5), oldest first. */
        @Builder.Default
        private List<SessionDecisionRecord> sessionDecisions = new ArrayList<>();
        /**
         * The device the session first came from and this request's when their operating system or browser differs,
         * "first -> current" (W2-14).
         */
        private String sessionDeviceChange;
        /** The network the session first came from and this request's when they differ, "first -> current" (W2-14). */
        private String sessionNetworkChange;
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
        /** The usual behaviour the values above come from, when the work profile collector computed one (W2-3). */
        private BaselineView baselineView;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RoleScopeProfile {
        private String summary;
        /**
         * The request's resource category ({@link Resource#getResourceCategory()}), compared with the expected and
         * forbidden resource families, which are categories too; never a class (W2-10).
         */
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
        /** Whether the current resource family is in denied scope, compared by refused pairs; null when unknown. */
        private Boolean currentResourceFamilyInDeniedScope;
        /** Whether the current action family is in denied scope, compared by refused pairs; null when unknown. */
        private Boolean currentActionFamilyInDeniedScope;
        /** True when the collector compared denied scope by refused pairs; the two values above then decide it. */
        private Boolean deniedScopeComparedByPair;
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
        public static final String RECORD_APPROVAL = "APPROVAL";
        public static final String RECORD_TICKET = "TICKET";
        public static final String RECORD_ON_CALL = "ON_CALL";
        public static final String RECORD_TRAVEL = "TRAVEL";
        public static final String RECORD_ASSIGNMENT = "ASSIGNMENT";
        public static final String RECORD_ACCESS_HISTORY = "ACCESS_HISTORY";

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
        /**
         * The approval records the host found for the request, as its records state them. Whether one covers the
         * request at the request time is computed by the engine (W2-5); the host's own verdict stays for comparison.
         */
        @Builder.Default
        private List<ApprovalRecord> approvalRecords = new ArrayList<>();
        /** The tickets the host found for the request, including one the requester named in the request. */
        @Builder.Default
        private List<TicketRecord> ticketRecords = new ArrayList<>();
        private OnCallRecord onCall;
        private TravelRecord travel;
        private AssignmentRecord assignment;
        private AccessHistoryRecord accessHistory;
        /** The company rules that apply to the request: what covers it and the exceptions. */
        @Builder.Default
        private List<CompanyPolicy> policies = new ArrayList<>();
        /**
         * The kinds of record the host looked up for the request ({@link #RECORD_APPROVAL}, {@link #RECORD_TICKET},
         * {@link #RECORD_ON_CALL}, {@link #RECORD_TRAVEL}, {@link #RECORD_ASSIGNMENT},
         * {@link #RECORD_ACCESS_HISTORY}). A kind it looked up and did not find is a fact (no ticket found); a kind
         * it did not look up is not known (P2 correction 3).
         */
        @Builder.Default
        private List<String> checkedRecordKinds = new ArrayList<>();

    }

    /** One approval record of the host's company records (W2-6). */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ApprovalRecord {
        private String approvalId;
        /** The record's state as the host names it (APPROVED, PENDING, REJECTED, EXPIRED). */
        private String status;
        private String approver;
        private String purpose;
        /** What the approval covers, by the host's key (for example a project key). */
        private String target;
        /** The most items the approval allows; null when it sets no limit. */
        private Integer maxItems;
        /** Items already used under the approval before this request; null when the host does not know. */
        private Integer usedItems;
        private Instant validFrom;
        private Instant validUntil;
        /** When the decision was recorded; null when the record does not say or nothing is decided yet. */
        private Instant decidedAt;
        @Builder.Default
        private List<String> pendingApprovers = new ArrayList<>();
        private Boolean breakGlass;
        /** The host's own verdict: whether the record covers this request, and the conditions it fails. */
        private Boolean hostCovers;
        @Builder.Default
        private List<String> hostMismatches = new ArrayList<>();
    }

    /** One ticket of the host's company records (W2-6). */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TicketRecord {
        private String ticketId;
        /** The kind of ticket as the host names it (CHANGE, INCIDENT). */
        private String kind;
        private String status;
        private String approver;
        private String purpose;
        private String target;
        private Instant validFrom;
        private Instant validUntil;
        /** Whether the requester named this ticket in the request (a claim the host checked). */
        private Boolean claimedByRequester;
        /** For a claimed ticket: whether it exists for the requester. */
        private Boolean exists;
        private Boolean hostCovers;
        @Builder.Default
        private List<String> hostMismatches = new ArrayList<>();
    }

    /** Whether the requester is on call at the request time (W2-6). */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class OnCallRecord {
        private Boolean onCall;
        private String rosterId;
        private String team;
        private Instant startsAt;
        private Instant endsAt;
    }

    /** The requester's registered business trip whose network contains the request address (W2-6). */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TravelRecord {
        private String planId;
        private String city;
        private String country;
        private String network;
    }

    /** Whether the requester is assigned to the request's target (W2-6). */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AssignmentRecord {
        private String target;
        private Boolean assigned;
        private String responsibility;
    }

    /** The requester's days with access to the request's target within a window before the request (W2-6). */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AccessHistoryRecord {
        private String target;
        private Integer days;
        private Integer windowDays;
        private String lastAccessDate;
    }

    /** A company rule that applies to the request: the record that covers it and the exceptions (W2-6). */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CompanyPolicy {
        private String policyId;
        private String statement;
        /** What covers a request under the rule: APPROVAL, or TICKET (of {@link #requiredTicketKind} when set). */
        private String requirement;
        private String requiredTicketKind;
        @Builder.Default
        private List<PolicyException> exceptions = new ArrayList<>();
        /** The host's own verdict: whether the rule requires a covering record for this request. */
        private Boolean hostRequires;
    }

    /**
     * An exception of a company rule: ASSIGNED (assigned to the target, up to {@link #limit} items when set),
     * ACCOUNT_MANAGER, RECENT_WORK (access within the last {@link #limit} days), or TICKET_WHILE_ON_CALL.
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PolicyException {
        private String kind;
        private Integer limit;
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