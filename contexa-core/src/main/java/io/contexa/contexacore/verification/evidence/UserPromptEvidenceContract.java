package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Canonical packaging contract between the LLM-view user prompt and the sealed
 * evidence package. The stored manifest is language-neutral: stable codes and
 * i18n keys are authoritative; English text is only the default fallback.
 */
final class UserPromptEvidenceContract {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private static final String P0_REQUIRED = "P0_REQUIRED";
    private static final String P1_REQUIRED_WITH_DECLARED_ABSENCE = "P1_REQUIRED_WITH_DECLARED_ABSENCE";
    private static final String RELEVANCE_LLM_DECISION_CONTRACT = "LLM_DECISION_CONTRACT";
    private static final String RELEVANCE_LLM_DECISION_SUPPORTING = "LLM_DECISION_SUPPORTING";
    private static final String RELEVANCE_AUDIT_ONLY_SEALED_SOURCE = "AUDIT_ONLY_SEALED_SOURCE";
    private static final String RELEVANCE_INTERNAL_RUNTIME_ONLY = "INTERNAL_RUNTIME_ONLY";

    private static final String PRODUCER_REQUEST_CONTEXT = "REQUEST_CONTEXT_PRODUCER";
    private static final String PRODUCER_AUTH_CONTEXT = "AUTH_CONTEXT_PRODUCER";
    private static final String PRODUCER_RESOURCE_CONTEXT = "RESOURCE_CONTEXT_PRODUCER";
    private static final String PRODUCER_BASELINE_CONTEXT = "BASELINE_CONTEXT_PRODUCER";
    private static final String PRODUCER_ROLE_SCOPE_CONTEXT = "ROLE_SCOPE_CONTEXT_PRODUCER";
    private static final String PRODUCER_WORK_PROFILE_CONTEXT = "WORK_PROFILE_CONTEXT_PRODUCER";
    private static final String PRODUCER_PROMPT_ASSEMBLER = "PROMPT_ASSEMBLER";
    private static final String PRODUCER_PROMPT_PROJECTION_TRACKER = "PROMPT_PROJECTION_TRACKER";
    private static final String PRODUCER_SOURCE_CONTEXT = "SOURCE_CONTEXT_PRODUCER";

    private static final String MSG_DECLARED_ABSENCE =
            "enterprise.pqa.promptEvidence.absence.declaredInExplicitMissingKnowledge";
    private static final String MSG_STATIC_PROJECTION_MISMATCH =
            "enterprise.pqa.promptEvidence.violation.staticProjectionMismatch";
    private static final String MSG_FIELD_STATE_CONTRACT_MISMATCH =
            "enterprise.pqa.promptEvidence.violation.fieldStateContractMismatch";
    private static final int FIELD_STATE_LEDGER_MANIFEST_LIMIT = 512;
    private static final int FIELD_STATE_LEDGER_TEXT_LIMIT = 512;

    private static final List<FieldSpec> FIELDS = List.of(
            p0("tenantId", "Tenant ID", List.of("TenantId", "TenantID"),
                    "REQUEST_FACTS", List.of("tenantId"), PRODUCER_REQUEST_CONTEXT, List.of("CCR", "CCSR")),
            p0("httpMethod", "HTTP method", List.of("HttpMethod", "HTTPMethod", "Method"),
                    "REQUEST_FACTS", List.of("httpMethod", "method"), PRODUCER_REQUEST_CONTEXT, List.of("CCR", "CCSR")),
            p0("requestPath", "Request path", List.of("RequestPath", "CurrentRequestPath", "Path"),
                    "REQUEST_FACTS", List.of("requestPath"), PRODUCER_REQUEST_CONTEXT, List.of("CCR", "PFR")),
            p0("resourceId", "Actual resource ID", List.of("ResourceId", "RequestedResourceId", "ProtectedResourceId"),
                    "REQUEST_FACTS", List.of("actualResourceId", "requestedResourceId", "resourceId", "protectedResourceId"),
                    PRODUCER_RESOURCE_CONTEXT, List.of("PRE", "CCR")),
            p0("clientIp", "Client IP", List.of("ClientIp", "ClientIP", "SourceIp"),
                    "REQUEST_FACTS", List.of("clientIp"), PRODUCER_REQUEST_CONTEXT, List.of("CCR")),
            p0("mfaVerified", "MFA verification state", List.of("MfaVerified", "MFAVerified"),
                    "AUTH_STATE", List.of("mfaVerified"), PRODUCER_AUTH_CONTEXT, List.of("CCR", "EIR")),
            p0("authorizationEffect", "Authorization effect", List.of("AuthorizationEffect"),
                    "AUTH_STATE", List.of("authorizationEffect"), PRODUCER_AUTH_CONTEXT, List.of("CCR", "PFR")),
            p0("effectiveRoles", "Effective roles", List.of("EffectiveRoles"),
                    "AUTH_STATE", List.of("effectiveRoles"), PRODUCER_AUTH_CONTEXT, List.of("CCR")),
            p0("authMethod", "Authentication method", List.of("AuthMethod", "AuthenticationType"),
                    "AUTH_STATE", List.of("authMethod"), PRODUCER_AUTH_CONTEXT, List.of("CCR")),
            p1("organizationId", "Organization ID", List.of("OrganizationId", "OrganizationID"),
                    "REQUEST_FACTS", List.of("organizationId"), PRODUCER_REQUEST_CONTEXT, List.of("CCR")),
            p1("requestId", "Request ID", List.of("RequestId", "RequestID"),
                    "REQUEST_FACTS", List.of("requestId"), PRODUCER_REQUEST_CONTEXT, List.of("MTR")),
            p1("correlationId", "Correlation ID", List.of("CorrelationId", "CorrelationID"),
                    "REQUEST_FACTS", List.of("correlationId"), PRODUCER_REQUEST_CONTEXT, List.of("MTR")),
            p1("effectivePermissions", "Effective permissions", List.of("EffectivePermissions"),
                    "AUTH_STATE", List.of("effectivePermissions"), PRODUCER_AUTH_CONTEXT, List.of("CCR")),
            p1("baselineProfileStatus", "Baseline profile status", List.of("BaselineProfileStatus"),
                    "BASELINE_SNAPSHOT", List.of("baselineProfileStatus"), PRODUCER_BASELINE_CONTEXT, List.of("BMA", "USNS")),
            p1("personalBaselineStatus", "Personal baseline status", List.of("PersonalBaselineStatus"),
                    "BASELINE_SNAPSHOT", List.of("personalBaselineStatus"), PRODUCER_BASELINE_CONTEXT, List.of("BMA", "USNS")),
            p1("baselineObservations", "Baseline observations", List.of("BaselineObservations"),
                    "BASELINE_SNAPSHOT", List.of("baselineObservations", "eventCount", "observationDays"),
                    PRODUCER_BASELINE_CONTEXT, List.of("BMA")),
            p1("observedPatternEvidenceScope", "Observed pattern evidence scope", List.of("ObservedPatternEvidenceScope"),
                    "BASELINE_SNAPSHOT", List.of("observedPatternEvidenceScope"), PRODUCER_BASELINE_CONTEXT, List.of("USNS")),
            p1("roleScopeEvidenceState", "Role scope evidence state", List.of("RoleScopeEvidenceState"),
                    "CANONICAL_CONTEXT", List.of("authorization.roleScopeEvidenceState", "roleScopeEvidenceState"),
                    PRODUCER_ROLE_SCOPE_CONTEXT, List.of("CCR", "PFR")),
            p1("workProfileEvidenceState", "Work profile evidence state", List.of("WorkProfileEvidenceState"),
                    "CANONICAL_CONTEXT", List.of("actor.workProfileEvidenceState", "workProfileEvidenceState"),
                    PRODUCER_WORK_PROFILE_CONTEXT, List.of("BMA", "USNS")),
            p1("userId", "User ID", List.of("User", "UserId"),
                    "REQUEST_FACTS", List.of("userId"), PRODUCER_REQUEST_CONTEXT, List.of("CCR", "CCSR")),
            p1("principalType", "Principal type", List.of("PrincipalType"),
                    "AUTH_STATE", List.of("principalType"), PRODUCER_AUTH_CONTEXT, List.of("CCR")),
            p1("failedLoginAttempts", "Failed login attempts", List.of("FailedLoginAttempts"),
                    "CANONICAL_CONTEXT", List.of("actor.failedLoginAttempts", "authentication.failedLoginAttempts"),
                    PRODUCER_AUTH_CONTEXT, List.of("CCR", "BSR")),
            p1("newDevice", "New device signal", List.of("NewDevice"),
                    "BASELINE_SNAPSHOT", List.of("isNewDevice"), PRODUCER_BASELINE_CONTEXT, List.of("USNS", "BSR")),
            p1("newSession", "New session signal", List.of("NewSession"),
                    "BASELINE_SNAPSHOT", List.of("isNewSession"), PRODUCER_BASELINE_CONTEXT, List.of("USNS", "BSR")),
            p1("newUser", "New user signal", List.of("NewUser"),
                    "BASELINE_SNAPSHOT", List.of("isNewUser"), PRODUCER_BASELINE_CONTEXT, List.of("USNS")),
            p1("recentRequestCount", "Recent request count", List.of("RecentRequestCount"),
                    "CANONICAL_CONTEXT", List.of("session.recentRequestCount", "session.requestCount"),
                    PRODUCER_BASELINE_CONTEXT, List.of("BSR")),
            p1("currentAccessHour", "Current access hour", List.of("CurrentAccessHour"),
                    "CANONICAL_CONTEXT", List.of("session.currentAccessHour", "workProfile.currentAccessHour"),
                    PRODUCER_BASELINE_CONTEXT, List.of("BMA", "USNS")),
            p1("deviceOs", "Device operating system", List.of("DeviceOs", "CurrentOperatingSystem"),
                    "CANONICAL_CONTEXT", List.of("device.os", "workProfile.currentOperatingSystem"),
                    PRODUCER_BASELINE_CONTEXT, List.of("USNS")),
            p1("deviceBrowser", "Device browser", List.of("DeviceBrowser", "CurrentBrowser"),
                    "CANONICAL_CONTEXT", List.of("device.browser", "workProfile.currentBrowser"),
                    PRODUCER_BASELINE_CONTEXT, List.of("USNS")),
            p1("deviceBrowserVersion", "Device browser version", List.of("DeviceBrowserVersion"),
                    "CANONICAL_CONTEXT", List.of("device.browserVersion"), PRODUCER_BASELINE_CONTEXT, List.of("USNS")),
            p1("deviceLanguage", "Device language", List.of("DeviceLanguage"),
                    "CANONICAL_CONTEXT", List.of("device.language"), PRODUCER_BASELINE_CONTEXT, List.of("USNS")),
            p1("ipBand", "IP band", List.of("IpBand"),
                    "CANONICAL_CONTEXT", List.of("location.ipBand"), PRODUCER_BASELINE_CONTEXT, List.of("USNS")),
            p1("botUserAgent", "Bot user-agent signal", List.of("BotUserAgent"),
                    "CANONICAL_CONTEXT", List.of("intent.botUserAgent"), PRODUCER_REQUEST_CONTEXT, List.of("BSR")),
            p1("missingReferer", "Missing referer signal", List.of("MissingReferer"),
                    "CANONICAL_CONTEXT", List.of("intent.missingReferer"), PRODUCER_REQUEST_CONTEXT, List.of("BSR")),
            p1("actionFamily", "Action family", List.of("ActionFamily", "CurrentActionFamily"),
                    "CANONICAL_CONTEXT", List.of("resource.actionFamily", "authorization.currentActionFamily"),
                    PRODUCER_RESOURCE_CONTEXT, List.of("PRE", "CCR")),
            p1("businessLabel", "Resource business label", List.of("BusinessLabel"),
                    "CANONICAL_CONTEXT", List.of("resource.businessLabel"), PRODUCER_RESOURCE_CONTEXT, List.of("PRE")),
            p1("sensitivity", "Resource sensitivity", List.of("Sensitivity"),
                    "CANONICAL_CONTEXT", List.of("resource.sensitivity"), PRODUCER_RESOURCE_CONTEXT, List.of("PRE")),
            p1("sensitiveResource", "Sensitive resource flag", List.of("SensitiveResource"),
                    "CANONICAL_CONTEXT", List.of("resource.sensitiveResource"), PRODUCER_RESOURCE_CONTEXT, List.of("PRE")),
            p1("resourceType", "Resource type", List.of("ResourceType"),
                    "CANONICAL_CONTEXT", List.of("resource.resourceType"), PRODUCER_RESOURCE_CONTEXT, List.of("PRE", "CCR")),
            p1("currentPathFamily", "Current path family", List.of("CurrentPathFamily"),
                    "CANONICAL_CONTEXT", List.of("resource.currentPathFamily", "workProfile.currentPathFamily"),
                    PRODUCER_RESOURCE_CONTEXT, List.of("PRE", "CCR")),
            p1("currentResourceFamily", "Current resource family", List.of("CurrentResourceFamily"),
                    "CANONICAL_CONTEXT", List.of("resource.currentResourceFamily", "authorization.currentResourceFamily"),
                    PRODUCER_RESOURCE_CONTEXT, List.of("PRE", "CCR")),
            p1("privilegedResource", "Privileged resource flag", List.of("PrivilegedResource"),
                    "CANONICAL_CONTEXT", List.of("resource.privilegedResource"), PRODUCER_RESOURCE_CONTEXT, List.of("PRE")),
            p1("exportSensitive", "Sensitive export flag", List.of("ExportSensitive"),
                    "CANONICAL_CONTEXT", List.of("resource.exportSensitive"), PRODUCER_RESOURCE_CONTEXT, List.of("PRE")),
            p1("sessionNarrativeSummary", "Session narrative summary", List.of("SessionNarrativeSummary"),
                    "CANONICAL_CONTEXT", List.of("sessionNarrativeProfile.summary"), PRODUCER_BASELINE_CONTEXT, List.of("BSR")),
            p1("previousPath", "Previous request path", List.of("PreviousPath"),
                    "CANONICAL_CONTEXT", List.of("sessionNarrativeProfile.previousPath"), PRODUCER_BASELINE_CONTEXT, List.of("BSR")),
            p1("lastRequestIntervalMs", "Last request interval", List.of("LastRequestIntervalMs"),
                    "CANONICAL_CONTEXT", List.of("sessionNarrativeProfile.lastRequestIntervalMs"), PRODUCER_BASELINE_CONTEXT, List.of("BSR")),
            p1("sessionActionSequence", "Session action sequence", List.of("SessionActionSequence"),
                    "CANONICAL_CONTEXT", List.of("sessionNarrativeProfile.actionSequence"), PRODUCER_BASELINE_CONTEXT, List.of("BSR")),
            p1("sessionProtectableSequence", "Session protectable resource sequence", List.of("SessionProtectableSequence"),
                    "CANONICAL_CONTEXT", List.of("sessionNarrativeProfile.protectableSequence"), PRODUCER_BASELINE_CONTEXT, List.of("BSR")),
            p1("burstPattern", "Burst pattern signal", List.of("BurstPattern"),
                    "CANONICAL_CONTEXT", List.of("sessionNarrativeProfile.burstPattern"), PRODUCER_BASELINE_CONTEXT, List.of("BSR")),
            p1("sessionAgeMinutes", "Session age in minutes", List.of("SessionAgeMinutes"),
                    "CANONICAL_CONTEXT", List.of("sessionNarrativeProfile.sessionAgeMinutes"), PRODUCER_BASELINE_CONTEXT, List.of("BSR")),
            p1("sessionRequestCount", "Session request count", List.of("SessionRequestCount"),
                    "CANONICAL_CONTEXT", List.of("sessionNarrativeProfile.sessionRequestCount"), PRODUCER_BASELINE_CONTEXT, List.of("BSR")),
            p1("sessionRequestsPerMinute", "Session requests per minute", List.of("SessionRequestsPerMinute"),
                    "CANONICAL_CONTEXT", List.of("sessionNarrativeProfile.sessionRequestsPerMinute"), PRODUCER_BASELINE_CONTEXT, List.of("BSR")),
            p1("currentAccessHourPresentInObservedHours", "Access hour baseline comparison", List.of("CurrentAccessHourPresentInObservedHours"),
                    "CANONICAL_CONTEXT", List.of("workProfile.currentAccessHourPresentInObservedHours"),
                    PRODUCER_BASELINE_CONTEXT, List.of("BMA", "USNS")),
            p1("currentNetworkPresentInObservedNetworks", "Network baseline comparison", List.of("CurrentNetworkPresentInObservedNetworks"),
                    "CANONICAL_CONTEXT", List.of("workProfile.currentNetworkPresentInObservedNetworks"),
                    PRODUCER_BASELINE_CONTEXT, List.of("BMA", "USNS")),
            p1("currentBrowserPresentInObservedBrowsers", "Browser baseline comparison", List.of("CurrentBrowserPresentInObservedBrowsers"),
                    "CANONICAL_CONTEXT", List.of("workProfile.currentBrowserPresentInObservedBrowsers"),
                    PRODUCER_BASELINE_CONTEXT, List.of("BMA", "USNS")),
            p1("currentRequestCombinationEvidenceScope", "Comparable request-combination evidence scope", List.of("CurrentRequestCombinationEvidenceScope"),
                    "CANONICAL_CONTEXT", List.of("workProfile.currentRequestCombinationEvidenceScope"),
                    PRODUCER_BASELINE_CONTEXT, List.of("BMA", "USNS")),
            p1("currentRequestCombinationSeenCount", "Comparable request-combination seen count", List.of("CurrentRequestCombinationSeenCount"),
                    "CANONICAL_CONTEXT", List.of("workProfile.currentRequestCombinationSeenCount"),
                    PRODUCER_BASELINE_CONTEXT, List.of("BMA", "USNS")),
            p1("recentPermissionChanges", "Recent permission changes", List.of("RecentPermissionChanges"),
                    "CANONICAL_CONTEXT", List.of("authorization.recentPermissionChanges"),
                    PRODUCER_ROLE_SCOPE_CONTEXT, List.of("CCR", "PFR")),
            p1("roleScopeDeltaCount", "Role scope delta count", List.of("RoleScopeDeltaCount"),
                    "CANONICAL_CONTEXT", List.of("authorization.roleScopeDeltaCount"),
                    PRODUCER_ROLE_SCOPE_CONTEXT, List.of("CCR", "PFR")),
            p1("currentActionFamilyPresentInExpectedRoleScope", "Expected role-scope action comparison", List.of("CurrentActionFamilyPresentInExpectedRoleScope"),
                    "CANONICAL_CONTEXT", List.of("authorization.currentActionFamilyPresentInExpectedRoleScope"),
                    PRODUCER_ROLE_SCOPE_CONTEXT, List.of("CCR", "PFR")),
            p1("currentActionFamilyPresentInDeniedRoleScope", "Denied role-scope action comparison", List.of("CurrentActionFamilyPresentInDeniedRoleScope"),
                    "CANONICAL_CONTEXT", List.of("authorization.currentActionFamilyPresentInDeniedRoleScope"),
                    PRODUCER_ROLE_SCOPE_CONTEXT, List.of("CCR", "PFR")),
            p1("elevatedPrivilegeWindowActive", "Elevated privilege window state", List.of("ElevatedPrivilegeWindowActive"),
                    "CANONICAL_CONTEXT", List.of("authorization.elevatedPrivilegeWindowActive"),
                    PRODUCER_ROLE_SCOPE_CONTEXT, List.of("CCR", "PFR")),
            p1("approvalRequired", "Approval required state", List.of("ApprovalRequired"),
                    "CANONICAL_CONTEXT", List.of("frictionProfile.approvalRequired"), PRODUCER_SOURCE_CONTEXT, List.of("BSR", "CCR")),
            p1("approvalGranted", "Approval granted state", List.of("ApprovalGranted"),
                    "CANONICAL_CONTEXT", List.of("frictionProfile.approvalGranted"), PRODUCER_SOURCE_CONTEXT, List.of("BSR", "CCR")),
            p1("approvalMissing", "Approval missing state", List.of("ApprovalMissing"),
                    "CANONICAL_CONTEXT", List.of("frictionProfile.approvalMissing"), PRODUCER_SOURCE_CONTEXT, List.of("BSR", "CCR")),
            p1("approvalStatus", "Approval status", List.of("ApprovalStatus"),
                    "CANONICAL_CONTEXT", List.of("frictionProfile.approvalStatus"), PRODUCER_SOURCE_CONTEXT, List.of("BSR", "CCR")),
            p1("delegated", "Delegated objective state", List.of("Delegated"),
                    "CANONICAL_CONTEXT", List.of("delegation.delegated"), PRODUCER_SOURCE_CONTEXT, List.of("CCR")),
            p1("objectiveFamily", "Objective family", List.of("ObjectiveFamily"),
                    "CANONICAL_CONTEXT", List.of("delegation.objectiveFamily"), PRODUCER_SOURCE_CONTEXT, List.of("CCR")),
            p1("objectiveSummary", "Objective summary", List.of("ObjectiveSummary"),
                    "CANONICAL_CONTEXT", List.of("delegation.objectiveSummary"), PRODUCER_SOURCE_CONTEXT, List.of("CCR")),
            p1("objectiveAlignmentEvidence", "Objective alignment evidence", List.of("ObjectiveAlignmentEvidence"),
                    "CANONICAL_CONTEXT", List.of("delegation.objectiveAlignmentEvidence"), PRODUCER_SOURCE_CONTEXT, List.of("CCR")),
            p1("coverageLevel", "Context coverage level", List.of("CoverageLevel"),
                    "CANONICAL_CONTEXT", List.of("coverage.coverageLevel"), PRODUCER_SOURCE_CONTEXT, List.of("CCR")),
            p1("coverageSummary", "Context coverage summary", List.of("CoverageSummary"),
                    "CANONICAL_CONTEXT", List.of("coverage.coverageSummary"), PRODUCER_SOURCE_CONTEXT, List.of("CCR")),
            p1("retrievalPurpose", "RAG retrieval purpose", List.of("RetrievalPurpose"),
                    "RAG_RESULTS", List.of("retrievalPurpose"), PRODUCER_SOURCE_CONTEXT, List.of("RAP")),
            p1("allowedDocumentCount", "Allowed retrieved document count", List.of("AllowedDocumentCount"),
                    "RAG_RESULTS", List.of("allowedDocumentCount"), PRODUCER_SOURCE_CONTEXT, List.of("RAP")),
            p1("deniedDocumentCount", "Denied retrieved document count", List.of("DeniedDocumentCount"),
                    "RAG_RESULTS", List.of("deniedDocumentCount"), PRODUCER_SOURCE_CONTEXT, List.of("RAP")),
            p1("relatedDocumentCount", "Related document count", List.of("RelatedDocumentCount"),
                    "RAG_RESULTS", List.of("relatedDocumentCount"), PRODUCER_SOURCE_CONTEXT, List.of("RAP")),
            p1("promptHash", "Prompt hash", List.of("PromptHash"),
                    "PROMPT_EXECUTION_METADATA", List.of("promptHash"), PRODUCER_PROMPT_ASSEMBLER, List.of("PFR", "MTR")),
            p1("userPromptHash", "User prompt hash", List.of("UserPromptHash"),
                    "PROMPT_EXECUTION_METADATA", List.of("userPromptHash"), PRODUCER_PROMPT_ASSEMBLER, List.of("PFR", "MTR")),
            p1("systemPromptHash", "System prompt hash", List.of("SystemPromptHash"),
                    "PROMPT_EXECUTION_METADATA", List.of("systemPromptHash"), PRODUCER_PROMPT_ASSEMBLER, List.of("PFR", "MTR"))
    );

    private UserPromptEvidenceContract() {
    }

    static Result evaluate(
            ObjectMapper objectMapper,
            String finalUserPrompt,
            String requestFactsJson,
            String authStateJson,
            String canonicalContextJson,
            String baselineSnapshotJson,
            String ragResultsJson,
            String promptExecutionMetadataJson,
            String decisionJson) {
        Map<String, Object> roots = new LinkedHashMap<>();
        roots.put("REQUEST_FACTS", readMap(objectMapper, requestFactsJson));
        roots.put("AUTH_STATE", readMap(objectMapper, authStateJson));
        roots.put("CANONICAL_CONTEXT", readMap(objectMapper, canonicalContextJson));
        roots.put("BASELINE_SNAPSHOT", readMap(objectMapper, baselineSnapshotJson));
        roots.put("RAG_RESULTS", readMap(objectMapper, ragResultsJson));
        roots.put("PROMPT_EXECUTION_METADATA", readMap(objectMapper, promptExecutionMetadataJson));
        roots.put("DECISION", readMap(objectMapper, decisionJson));

        List<Map<String, Object>> fields = new ArrayList<>();
        List<Map<String, Object>> violations = new ArrayList<>();
        Set<String> insertedFieldKeys = new LinkedHashSet<>();
        int p0Blocking = 0;
        int declaredAbsence = 0;

        for (FieldSpec spec : FIELDS) {
            String promptValue = firstPromptValue(finalUserPrompt, spec.promptLabels());
            EvidenceValue evidence = firstEvidenceValue(roots, spec);
            ProjectionState state = projectionState(spec, promptValue, evidence.value());
            if (isDeclaredAbsenceAllowed(spec, state, finalUserPrompt)) {
                state = ProjectionState.DECLARED_ABSENCE;
                declaredAbsence++;
            }
            boolean blocking = P0_REQUIRED.equals(spec.requiredLevel())
                    && state != ProjectionState.PRESENT;
            if (blocking) {
                p0Blocking++;
                violations.add(violation(spec, promptValue, evidence, state));
            }

            Map<String, Object> row = new LinkedHashMap<>();
            putFieldIdentity(row, spec.fieldKey(), spec.displayNameFallback());
            row.put("requiredLevel", spec.requiredLevel());
            row.put("promptLabels", spec.promptLabels());
            row.put("promptValue", promptValue);
            row.put("evidenceSection", evidence.section());
            row.put("evidencePath", evidence.path());
            row.put("evidenceValue", evidence.value());
            row.put("projectionState", state.name());
            row.put("declaredAbsence", state == ProjectionState.DECLARED_ABSENCE);
            if (state == ProjectionState.DECLARED_ABSENCE) {
                row.put("declaredAbsenceReasonCode", "DECLARED_IN_EXPLICIT_MISSING_KNOWLEDGE");
                row.put("declaredAbsenceReasonKey", MSG_DECLARED_ABSENCE);
                row.put("declaredAbsenceReason", declaredAbsenceFallback());
            }
            else {
                row.put("declaredAbsenceReasonCode", null);
                row.put("declaredAbsenceReasonKey", null);
                row.put("declaredAbsenceReason", null);
            }
            row.put("blocking", blocking);
            putProducer(row, spec.producerCode());
            row.put("metricCodes", spec.metricCodes());
            fields.add(row);
            insertedFieldKeys.add(spec.fieldKey());
        }

        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("contractVersion", "USER_PROMPT_EVIDENCE_CONTRACT_V1");
        manifest.put("messageLocalePolicy", "I18N_KEY_WITH_ENGLISH_FALLBACK");
        appendPromptFieldStateManifest(
                manifest,
                roots.get("PROMPT_EXECUTION_METADATA"),
                fields,
                violations,
                insertedFieldKeys);
        manifest.put("totalFieldCount", fields.size());
        manifest.put("presentFieldCount", countProjectionState(fields, ProjectionState.PRESENT.name()));
        manifest.put("declaredAbsenceFieldCount", declaredAbsence);
        int blockingCount = countBlocking(fields);
        manifest.put("p0BlockingCount", p0Blocking);
        manifest.put("blockingFieldCount", blockingCount);
        manifest.put("sealable", blockingCount == 0);
        manifest.put("fields", fields);
        manifest.put("violations", violations);

        return new Result(toJson(objectMapper, manifest), blockingCount == 0, violations);
    }

    @SuppressWarnings("unchecked")
    private static void appendPromptFieldStateManifest(
            Map<String, Object> manifest,
            Object promptMetadata,
            List<Map<String, Object>> fields,
            List<Map<String, Object>> violations,
            Set<String> insertedFieldKeys) {
        if (!(promptMetadata instanceof Map<?, ?> rawMetadata)) {
            manifest.put("fieldStateLedgerAvailable", false);
            manifest.put("fieldStateTotalCount", 0);
            manifest.put("fieldStateBlockingCount", 0);
            manifest.put("sourceContextFieldCount", 0);
            manifest.put("sourceContextExhaustive", false);
            return;
        }
        Map<String, Object> metadata = (Map<String, Object>) rawMetadata;
        Object ledger = metadata.get("promptFieldStateLedger");
        int ledgerCount = ledger instanceof Collection<?> collection
                ? collection.size()
                : intValue(metadata.get("promptFieldStateCount"), 0);
        int rawBlockingCount = intValue(metadata.get("promptBlockingFieldStateCount"), 0);
        manifest.put("fieldStateLedgerAvailable", ledgerCount > 0);
        manifest.put("fieldStateTotalCount", ledgerCount);
        manifest.put("fieldStateRawBlockingCount", rawBlockingCount);
        manifest.put("fieldStateBlockingCount", 0);
        manifest.put("fieldStateSummary", metadata.get("promptFieldStateSummary"));
        manifest.put("sourceContextFieldCount", intValue(metadata.get("promptSourceContextFieldCount"), 0));
        manifest.put("sourceContextExhaustive", Boolean.TRUE.equals(metadata.get("promptSourceContextExhaustive")));
        manifest.put("sourceContextFailureCount", intValue(metadata.get("promptSourceContextFailureCount"), 0));
        if (ledger instanceof List<?> rows) {
            List<Map<String, Object>> manifestLedger = new ArrayList<>();
            int finalPromptFieldCount = 0;
            int appendedFieldCount = 0;
            int appendedBlockingCount = 0;
            int manifestLedgerOmittedCount = 0;
            for (Object row : rows) {
                if (!(row instanceof Map<?, ?> fieldState)) {
                    continue;
                }
                boolean decisionContractField = isDecisionContractFieldState(fieldState);
                Map<String, Object> enriched = enrichFieldStateLedgerRow(fieldState, decisionContractField);
                String sourceType = stringValue(fieldState.get("sourceType"));
                boolean finalPromptField = "FINAL_USER_PROMPT_FIELD".equals(sourceType);
                if (finalPromptField) {
                    finalPromptFieldCount++;
                }
                if (storeManifestFieldStateLedgerRow(enriched, decisionContractField)) {
                    if (manifestLedger.size() < FIELD_STATE_LEDGER_MANIFEST_LIMIT) {
                        manifestLedger.add(compactManifestFieldStateLedgerRow(enriched));
                    }
                    else {
                        manifestLedgerOmittedCount++;
                    }
                }
                if (!decisionContractField) {
                    continue;
                }
                boolean blocking = Boolean.TRUE.equals(fieldState.get("blockingCandidate"));
                String fieldKey = stringValue(fieldState.get("fieldKey"));
                if (!StringUtils.hasText(fieldKey) || insertedFieldKeys.contains(fieldKey) || !blocking) {
                    continue;
                }
                Map<String, Object> manifestField = fieldStateManifestField(enriched, finalPromptField, blocking);
                fields.add(manifestField);
                insertedFieldKeys.add(fieldKey);
                appendedFieldCount++;
                if (Boolean.TRUE.equals(manifestField.get("blocking"))) {
                    violations.add(fieldStateViolation(manifestField));
                    appendedBlockingCount++;
                }
            }
            manifest.put("finalUserPromptFieldCount", finalPromptFieldCount);
            manifest.put("appendedFieldStateFieldCount", appendedFieldCount);
            manifest.put("appendedFieldStateBlockingCount", appendedBlockingCount);
            manifest.put("fieldStateBlockingCount", appendedBlockingCount);
            manifest.put("fieldStateLedgerStoragePolicy", "OFFICIAL_RELEVANT_COMPACT_ROWS");
            manifest.put("fieldStateLedgerStoredCount", manifestLedger.size());
            manifest.put("fieldStateLedgerOmittedCount", manifestLedgerOmittedCount);
            manifest.put("fieldStateLedger", manifestLedger);
        }
        else {
            manifest.put("fieldStateLedgerStoragePolicy", ledger == null ? "ABSENT" : "OMITTED_NON_LIST_VALUE");
            manifest.put("fieldStateLedgerStoredCount", 0);
            manifest.put("fieldStateLedgerOmittedCount", ledger == null ? 0 : 1);
            manifest.put("fieldStateLedger", List.of());
        }
    }

    private static boolean storeManifestFieldStateLedgerRow(Map<String, Object> enriched, boolean decisionContractField) {
        return decisionContractField
                || Boolean.TRUE.equals(enriched.get("officialBlockingCandidate"))
                || Boolean.TRUE.equals(enriched.get("blockingCandidate"))
                || hasManifestMetricCodes(enriched.get("metricCodes"));
    }

    private static boolean hasManifestMetricCodes(Object value) {
        if (value instanceof Collection<?> collection) {
            return !collection.isEmpty();
        }
        return false;
    }

    private static Map<String, Object> compactManifestFieldStateLedgerRow(Map<String, Object> source) {
        Map<String, Object> compact = new LinkedHashMap<>();
        copyManifestFieldStateValue(compact, source, "fieldKey");
        copyManifestFieldStateValue(compact, source, "sourceType");
        copyManifestFieldStateValue(compact, source, "sourceClass");
        copyManifestFieldStateValue(compact, source, "sourceFieldPath");
        copyManifestFieldStateValue(compact, source, "promptSection");
        copyManifestFieldStateValue(compact, source, "promptPresenceState");
        copyManifestFieldStateValue(compact, source, "promptLabel");
        copyManifestFieldStateValue(compact, source, "valueType");
        copyManifestFieldStateValue(compact, source, "requiredPolicy");
        copyManifestFieldStateValue(compact, source, "projectionPolicy");
        copyManifestFieldStateValue(compact, source, "applicabilityRule");
        copyManifestFieldStateValue(compact, source, "qualityRelevance");
        copyManifestFieldStateValue(compact, source, "metricCodes");
        copyManifestFieldStateValue(compact, source, "metricBindingStatus");
        copyManifestFieldStateValue(compact, source, "remediationOwner");
        copyManifestFieldStateValue(compact, source, "producerStatus");
        copyManifestFieldStateValue(compact, source, "notApplicableRule");
        copyManifestFieldStateValue(compact, source, "fieldState");
        copyManifestFieldStateValue(compact, source, "absenceReasonText");
        copyManifestFieldStateValue(compact, source, "valuePreview");
        copyManifestFieldStateValue(compact, source, "blockingCandidate");
        copyManifestFieldStateValue(compact, source, "rawBlockingCandidate");
        copyManifestFieldStateValue(compact, source, "officialBlockingCandidate");
        return compact;
    }

    private static void copyManifestFieldStateValue(
            Map<String, Object> target,
            Map<String, Object> source,
            String key) {
        if (!source.containsKey(key)) {
            return;
        }
        Object value = source.get(key);
        if (value instanceof String text && text.length() > FIELD_STATE_LEDGER_TEXT_LIMIT) {
            target.put(key, text.substring(0, FIELD_STATE_LEDGER_TEXT_LIMIT));
            target.put(key + "Truncated", true);
            target.put(key + "OriginalLength", text.length());
            return;
        }
        target.put(key, value);
    }

    private static Map<String, Object> fieldStateManifestField(
            Map<?, ?> fieldState,
            boolean finalPromptField,
            boolean blocking) {
        String fieldStateName = stringValue(fieldState.get("fieldState"));
        String fieldKey = stringValue(fieldState.get("fieldKey"));
        String label = firstNonBlank(
                stringValue(fieldState.get("promptLabel")),
                stringValue(fieldState.get("sourceFieldPath")),
                fieldKey);
        String value = stringValue(fieldState.get("valuePreview"));
        String projectionState = finalPromptField && !blocking
                ? ProjectionState.PRESENT.name()
                : projectionStateFromFieldState(fieldStateName);
        Map<String, Object> row = new LinkedHashMap<>();
        putFieldIdentity(row, fieldKey, label);
        row.put("requiredLevel", stringValue(fieldState.get("requiredPolicy")));
        row.put("promptLabels", List.of(label));
        row.put("promptValue", finalPromptField ? value : null);
        row.put("evidenceSection", sourceTypeToEvidenceSection(stringValue(fieldState.get("sourceType"))));
        row.put("evidencePath", stringValue(fieldState.get("sourceFieldPath")));
        row.put("evidenceValue", value);
        row.put("projectionState", projectionState);
        row.put("declaredAbsence", false);
        row.put("declaredAbsenceReasonCode", null);
        row.put("declaredAbsenceReasonKey", null);
        row.put("declaredAbsenceReason", null);
        row.put("blocking", blocking);
        row.put("qualityRelevance", stringValue(fieldState.get("qualityRelevance")));
        row.put("rawBlockingCandidate", Boolean.TRUE.equals(fieldState.get("rawBlockingCandidate")));
        row.put("officialBlockingCandidate", Boolean.TRUE.equals(fieldState.get("officialBlockingCandidate")));
        row.put("fieldState", fieldStateName);
        row.put("fieldStateReason", stringValue(fieldState.get("absenceReasonText")));
        putProducer(row, producerCodeForFieldState(fieldState));
        row.put("metricCodes", metricCodesForFieldState(fieldState));
        row.put("metricBindingStatus", row.get("metricCodes") instanceof List<?> codes && !codes.isEmpty()
                ? "BOUND_FROM_SOURCE"
                : "UNBOUND_SOURCE_FIELD");
        return row;
    }

    private static Map<String, Object> enrichFieldStateLedgerRow(Map<?, ?> fieldState, boolean decisionContractField) {
        Map<String, Object> enriched = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : fieldState.entrySet()) {
            if (entry.getKey() != null) {
                enriched.put(String.valueOf(entry.getKey()), entry.getValue());
            }
        }
        if (metricCodesForFieldState(fieldState).isEmpty()) {
            List<String> metricCodes = metricCodesForDecisionContractFieldState(fieldState);
            if (!metricCodes.isEmpty()) {
                enriched.put("metricCodes", metricCodes);
                enriched.put("metricBindingStatus", "BOUND_FROM_DECISION_CONTRACT");
            }
        }
        boolean rawBlocking = Boolean.TRUE.equals(fieldState.get("blockingCandidate"));
        boolean officialBlocking = decisionContractField && rawBlocking;
        enriched.put("qualityRelevance", qualityRelevanceForFieldState(fieldState, decisionContractField));
        enriched.put("rawBlockingCandidate", rawBlocking);
        enriched.put("officialBlockingCandidate", officialBlocking);
        enriched.put("blockingCandidate", officialBlocking);
        return enriched;
    }

    private static boolean isDecisionContractFieldState(Map<?, ?> fieldState) {
        if (RELEVANCE_LLM_DECISION_CONTRACT.equals(normalizeEnum(stringValue(fieldState.get("qualityRelevance"))))) {
            return true;
        }
        return matchingFieldSpec(fieldState) != null;
    }

    private static List<String> metricCodesForDecisionContractFieldState(Map<?, ?> fieldState) {
        FieldSpec spec = matchingFieldSpec(fieldState);
        return spec == null ? List.of() : spec.metricCodes();
    }

    private static FieldSpec matchingFieldSpec(Map<?, ?> fieldState) {
        String fieldKey = normalizeContractProbe(stringValue(fieldState.get("fieldKey")));
        String sourcePath = normalizeContractProbe(stringValue(fieldState.get("sourceFieldPath")));
        String promptLabel = normalizeContractProbe(stringValue(fieldState.get("promptLabel")));
        for (FieldSpec spec : FIELDS) {
            if (fieldKey.equals(normalizeContractProbe(spec.fieldKey()))) {
                return spec;
            }
            if (promptLabelMatchesSpec(promptLabel, spec) && sourcePathMatchesSpec(sourcePath, spec)) {
                return spec;
            }
        }
        return null;
    }

    private static boolean promptLabelMatchesSpec(String promptLabel, FieldSpec spec) {
        if (!StringUtils.hasText(promptLabel)) {
            return false;
        }
        for (String label : spec.promptLabels()) {
            if (promptLabel.equals(normalizeContractProbe(label))) {
                return true;
            }
        }
        return false;
    }

    private static boolean sourcePathMatchesSpec(String sourcePath, FieldSpec spec) {
        if (!StringUtils.hasText(sourcePath)) {
            return false;
        }
        for (String evidencePath : spec.evidencePaths()) {
            if (sourcePath.equals(normalizeContractProbe(evidencePath))) {
                return true;
            }
        }
        return false;
    }

    private static String qualityRelevanceForFieldState(Map<?, ?> fieldState, boolean decisionContractField) {
        if (decisionContractField) {
            return RELEVANCE_LLM_DECISION_CONTRACT;
        }
        String explicit = normalizeEnum(stringValue(fieldState.get("qualityRelevance")));
        if (RELEVANCE_LLM_DECISION_SUPPORTING.equals(explicit)
                || RELEVANCE_AUDIT_ONLY_SEALED_SOURCE.equals(explicit)
                || RELEVANCE_INTERNAL_RUNTIME_ONLY.equals(explicit)) {
            return explicit;
        }
        return RELEVANCE_AUDIT_ONLY_SEALED_SOURCE;
    }

    private static String normalizeEnum(String value) {
        return StringUtils.hasText(value)
                ? value.trim().replace('-', '_').replace(' ', '_').toUpperCase(Locale.ROOT)
                : "";
    }

    private static Map<String, Object> fieldStateViolation(Map<String, Object> field) {
        Map<String, Object> violation = new LinkedHashMap<>();
        violation.put("fieldKey", field.get("fieldKey"));
        violation.put("displayName", field.get("displayName"));
        violation.put("displayNameKey", field.get("displayNameKey"));
        violation.put("displayNameFallback", field.get("displayNameFallback"));
        violation.put("requiredLevel", field.get("requiredLevel"));
        violation.put("projectionState", field.get("projectionState"));
        violation.put("promptValue", field.get("promptValue"));
        violation.put("evidenceSection", field.get("evidenceSection"));
        violation.put("evidencePath", field.get("evidencePath"));
        violation.put("evidenceValue", field.get("evidenceValue"));
        violation.put("producer", field.get("producer"));
        violation.put("producerCode", field.get("producerCode"));
        violation.put("producerKey", field.get("producerKey"));
        violation.put("producerFallback", field.get("producerFallback"));
        violation.put("messageCode", "FIELD_STATE_CONTRACT_MISMATCH");
        violation.put("messageKey", MSG_FIELD_STATE_CONTRACT_MISMATCH);
        violation.put("messageArguments", messageArguments(field));
        violation.put("message", field.get("displayName")
                + " does not satisfy the actual prompt and sealed evidence field-state contract.");
        return violation;
    }

    private static String projectionStateFromFieldState(String fieldState) {
        return switch (normalizeState(fieldState)) {
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> ProjectionState.MISSING_IN_PROMPT.name();
            case "UNKNOWN_WITHOUT_REASON", "CONTRACT_MISMATCH" -> ProjectionState.VALUE_MISMATCH.name();
            default -> ProjectionState.PRESENT.name();
        };
    }

    private static String normalizeState(String value) {
        return firstNonBlank(value, "").toUpperCase(Locale.ROOT);
    }

    private static List<String> metricCodesForFieldState(Map<?, ?> fieldState) {
        Object metricCodes = fieldState.get("metricCodes");
        if (metricCodes instanceof Collection<?> collection) {
            return collection.stream()
                    .map(UserPromptEvidenceContract::stringValue)
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
        }
        String metricCode = stringValue(fieldState.get("metricCode"));
        return StringUtils.hasText(metricCode) ? List.of(metricCode) : List.of();
    }

    private static String producerCodeForFieldState(Map<?, ?> fieldState) {
        String sourceType = stringValue(fieldState.get("sourceType"));
        if ("FINAL_USER_PROMPT_FIELD".equals(sourceType) || "RAW_USER_PROMPT_FIELD".equals(sourceType)) {
            return PRODUCER_PROMPT_ASSEMBLER;
        }
        if ("PROMPT_PROJECTION_DIFF".equals(sourceType)) {
            return PRODUCER_PROMPT_PROJECTION_TRACKER;
        }
        return PRODUCER_SOURCE_CONTEXT;
    }

    private static String sourceTypeToEvidenceSection(String sourceType) {
        if (!StringUtils.hasText(sourceType)) {
            return "FIELD_STATE_LEDGER";
        }
        return sourceType;
    }

    private static int countProjectionState(List<Map<String, Object>> fields, String projectionState) {
        int count = 0;
        for (Map<String, Object> field : fields) {
            if (projectionState.equals(String.valueOf(field.get("projectionState")))) {
                count++;
            }
        }
        return count;
    }

    private static int countBlocking(List<Map<String, Object>> fields) {
        int count = 0;
        for (Map<String, Object> field : fields) {
            if (Boolean.TRUE.equals(field.get("blocking"))) {
                count++;
            }
        }
        return count;
    }

    private static int intValue(Object value, int fallback) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text) {
            try {
                return Integer.parseInt(text.trim());
            }
            catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    private static String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return "";
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private static FieldSpec p0(
            String fieldKey,
            String displayNameFallback,
            List<String> promptLabels,
            String evidenceSection,
            List<String> evidencePaths,
            String producerCode,
            List<String> metricCodes) {
        return new FieldSpec(fieldKey, displayNameFallback, P0_REQUIRED, promptLabels, evidenceSection, evidencePaths, producerCode, metricCodes);
    }

    private static FieldSpec p1(
            String fieldKey,
            String displayNameFallback,
            List<String> promptLabels,
            String evidenceSection,
            List<String> evidencePaths,
            String producerCode,
            List<String> metricCodes) {
        return new FieldSpec(fieldKey, displayNameFallback, P1_REQUIRED_WITH_DECLARED_ABSENCE, promptLabels, evidenceSection, evidencePaths, producerCode, metricCodes);
    }

    private static Map<String, Object> readMap(ObjectMapper objectMapper, String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(json, MAP_TYPE);
            return parsed == null ? Map.of() : parsed;
        } catch (JsonProcessingException ignored) {
            return Map.of();
        }
    }

    private static String firstPromptValue(String prompt, List<String> labels) {
        for (String label : labels) {
            String value = extractLineValue(prompt, label);
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private static String extractLineValue(String prompt, String label) {
        if (!StringUtils.hasText(prompt) || !StringUtils.hasText(label)) {
            return null;
        }
        String prefix = label + ":";
        for (String line : prompt.split("\\R")) {
            String trimmed = line == null ? "" : line.trim();
            if (trimmed.regionMatches(true, 0, prefix, 0, prefix.length())) {
                return normalizePromptScalar(trimmed.substring(prefix.length()));
            }
            int assignmentIndex = trimmed.indexOf('=');
            if (assignmentIndex > 0
                    && trimmed.substring(0, assignmentIndex).trim().equalsIgnoreCase(label.trim())) {
                return normalizePromptScalar(trimmed.substring(assignmentIndex + 1));
            }
        }
        return null;
    }

    private static String normalizePromptScalar(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.length() >= 2
                && ((normalized.startsWith("\"") && normalized.endsWith("\""))
                || (normalized.startsWith("'") && normalized.endsWith("'")))) {
            normalized = normalized.substring(1, normalized.length() - 1).trim();
        }
        return normalized;
    }

    private static EvidenceValue firstEvidenceValue(Map<String, Object> roots, FieldSpec spec) {
        Object root = roots.get(spec.evidenceSection());
        for (String path : spec.evidencePaths()) {
            Object value = readPath(root, path);
            String normalized = stringify(value);
            if (StringUtils.hasText(normalized)) {
                return new EvidenceValue(spec.evidenceSection(), path, normalized);
            }
        }
        String fallbackPath = spec.evidencePaths().isEmpty() ? "" : spec.evidencePaths().get(0);
        return new EvidenceValue(spec.evidenceSection(), fallbackPath, null);
    }

    @SuppressWarnings("unchecked")
    private static Object readPath(Object root, String path) {
        if (root == null || !StringUtils.hasText(path)) {
            return null;
        }
        Object current = root;
        for (String part : path.split("\\.")) {
            if (!(current instanceof Map<?, ?> map)) {
                return null;
            }
            current = ((Map<String, Object>) map).get(part);
            if (current == null) {
                return null;
            }
        }
        return current;
    }

    private static String stringify(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Collection<?> collection) {
            return collection.stream()
                    .map(UserPromptEvidenceContract::stringify)
                    .filter(StringUtils::hasText)
                    .toList()
                    .toString();
        }
        if (value instanceof Map<?, ?> map) {
            return map.toString();
        }
        return String.valueOf(value).trim();
    }

    private static ProjectionState projectionState(FieldSpec spec, String promptValue, String evidenceValue) {
        boolean promptMissing = !StringUtils.hasText(promptValue);
        boolean evidenceMissing = !StringUtils.hasText(evidenceValue);
        if (promptMissing && evidenceMissing) {
            return ProjectionState.MISSING_IN_BOTH;
        }
        if (promptMissing) {
            return ProjectionState.MISSING_IN_PROMPT;
        }
        if (evidenceMissing) {
            return ProjectionState.MISSING_IN_EVIDENCE;
        }
        return valuesEquivalent(spec, promptValue, evidenceValue) ? ProjectionState.PRESENT : ProjectionState.VALUE_MISMATCH;
    }

    private static boolean isDeclaredAbsenceAllowed(FieldSpec spec, ProjectionState state, String finalUserPrompt) {
        if (!P1_REQUIRED_WITH_DECLARED_ABSENCE.equals(spec.requiredLevel())) {
            return false;
        }
        if (state == ProjectionState.PRESENT || state == ProjectionState.VALUE_MISMATCH) {
            return false;
        }
        return containsExplicitMissingKnowledge(finalUserPrompt);
    }

    private static boolean containsExplicitMissingKnowledge(String prompt) {
        return StringUtils.hasText(prompt)
                && prompt.toUpperCase(Locale.ROOT).contains("EXPLICIT MISSING KNOWLEDGE");
    }

    private static boolean valuesEquivalent(FieldSpec spec, String promptValue, String evidenceValue) {
        String prompt = clean(promptValue);
        String evidence = clean(evidenceValue);
        if (prompt.equals(evidence)) {
            return true;
        }
        return isListSetComparisonField(spec) && tokenSet(prompt).equals(tokenSet(evidence));
    }

    private static boolean isListSetComparisonField(FieldSpec spec) {
        if (spec == null) {
            return false;
        }
        String fieldKey = normalizeContractProbe(spec.fieldKey());
        return "EFFECTIVE_ROLES".equals(fieldKey)
                || "EFFECTIVE_PERMISSIONS".equals(fieldKey);
    }

    private static Set<String> tokenSet(String value) {
        if (!StringUtils.hasText(value)) {
            return Set.of();
        }
        Set<String> tokens = new LinkedHashSet<>();
        for (String token : value.split(",")) {
            String normalized = token.trim();
            if (StringUtils.hasText(normalized)) {
                tokens.add(normalized);
            }
        }
        return tokens;
    }

    private static String clean(String value) {
        return value == null
                ? ""
                : value.trim()
                .replace("[", "")
                .replace("]", "")
                .replace("\"", "")
                .replace("'", "")
                .replaceAll("\\s+", " ")
                .toLowerCase(Locale.ROOT);
    }

    private static Map<String, Object> violation(
            FieldSpec spec,
            String promptValue,
            EvidenceValue evidence,
            ProjectionState state) {
        Map<String, Object> violation = new LinkedHashMap<>();
        putFieldIdentity(violation, spec.fieldKey(), spec.displayNameFallback());
        violation.put("requiredLevel", spec.requiredLevel());
        violation.put("projectionState", state.name());
        violation.put("promptValue", promptValue);
        violation.put("evidenceSection", evidence.section());
        violation.put("evidencePath", evidence.path());
        violation.put("evidenceValue", evidence.value());
        putProducer(violation, spec.producerCode());
        violation.put("messageCode", "STATIC_PROJECTION_MISMATCH");
        violation.put("messageKey", MSG_STATIC_PROJECTION_MISMATCH);
        violation.put("messageArguments", messageArguments(violation));
        violation.put("message", spec.displayNameFallback()
                + " is not confirmed with the same value in the final user prompt and sealed evidence package.");
        return violation;
    }

    private static void putFieldIdentity(Map<String, Object> row, String fieldKey, String displayNameFallback) {
        String normalizedFieldKey = firstNonBlank(fieldKey, "unknown");
        String fallback = firstNonBlank(displayNameFallback, normalizedFieldKey);
        row.put("fieldKey", normalizedFieldKey);
        row.put("displayNameKey", "enterprise.pqa.prompt.field." + i18nSuffix(normalizedFieldKey));
        row.put("displayNameFallback", fallback);
        row.put("displayName", fallback);
    }

    private static void putProducer(Map<String, Object> row, String producerCode) {
        String code = firstNonBlank(producerCode, PRODUCER_SOURCE_CONTEXT);
        String fallback = producerFallback(code);
        row.put("producerCode", code);
        row.put("producerKey", "enterprise.pqa.prompt.producer." + i18nSuffix(code));
        row.put("producerFallback", fallback);
        row.put("producer", fallback);
    }

    private static String producerFallback(String producerCode) {
        return switch (producerCode) {
            case PRODUCER_REQUEST_CONTEXT -> "Request context producer";
            case PRODUCER_AUTH_CONTEXT -> "Authentication and authorization context producer";
            case PRODUCER_RESOURCE_CONTEXT -> "Resource context producer";
            case PRODUCER_BASELINE_CONTEXT -> "Baseline context producer";
            case PRODUCER_ROLE_SCOPE_CONTEXT -> "Role scope context producer";
            case PRODUCER_WORK_PROFILE_CONTEXT -> "Work profile context producer";
            case PRODUCER_PROMPT_ASSEMBLER -> "Prompt assembler";
            case PRODUCER_PROMPT_PROJECTION_TRACKER -> "Prompt projection tracker";
            default -> "Source context producer";
        };
    }

    private static String declaredAbsenceFallback() {
        return "The final user prompt declares this context gap in the EXPLICIT MISSING KNOWLEDGE section.";
    }

    private static Map<String, Object> messageArguments(Map<String, Object> source) {
        Map<String, Object> args = new LinkedHashMap<>();
        args.put("fieldKey", source.get("fieldKey"));
        args.put("displayName", source.get("displayName"));
        args.put("projectionState", source.get("projectionState"));
        args.put("evidenceSection", source.get("evidenceSection"));
        args.put("evidencePath", source.get("evidencePath"));
        args.put("producerCode", source.get("producerCode"));
        return args;
    }

    private static String i18nSuffix(String value) {
        String suffix = firstNonBlank(value, "unknown")
                .replaceAll("[^A-Za-z0-9]+", ".")
                .replaceAll("^\\.+", "")
                .replaceAll("\\.+$", "")
                .toLowerCase(Locale.ROOT);
        return StringUtils.hasText(suffix) ? suffix : "unknown";
    }

    private static String normalizeContractProbe(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim()
                .replaceAll("([a-z])([A-Z])", "$1_$2")
                .replaceAll("[^\\p{IsAlphabetic}\\p{IsDigit}]+", ".")
                .replaceAll("\\.+", ".")
                .replaceAll("^\\.|\\.$", "")
                .toUpperCase(Locale.ROOT);
    }

    private static String toJson(ObjectMapper objectMapper, Map<String, Object> value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize user prompt evidence manifest", e);
        }
    }

    enum ProjectionState {
        PRESENT,
        MISSING_IN_PROMPT,
        MISSING_IN_EVIDENCE,
        MISSING_IN_BOTH,
        DECLARED_ABSENCE,
        VALUE_MISMATCH
    }

    record Result(String manifestJson, boolean sealable, List<Map<String, Object>> violations) {
    }

    private record FieldSpec(
            String fieldKey,
            String displayNameFallback,
            String requiredLevel,
            List<String> promptLabels,
            String evidenceSection,
            List<String> evidencePaths,
            String producerCode,
            List<String> metricCodes) {
    }

    private record EvidenceValue(String section, String path, String value) {
    }
}
