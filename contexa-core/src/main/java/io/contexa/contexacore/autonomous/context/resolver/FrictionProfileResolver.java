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
package io.contexa.contexacore.autonomous.context.resolver;

import java.util.Set;
import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.decision.CompanyRecordsEvaluator;
import io.contexa.contexacore.autonomous.context.decision.RecordCheck;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static io.contexa.contexacore.autonomous.context.support.MetadataValueResolver.normalizeSequence;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;

/**
 * Resolves FrictionProfile from metadata.
 * Extracted from DefaultCanonicalSecurityContextProvider - all business logic preserved.
 */
public class FrictionProfileResolver extends AbstractProfileResolver<FrictionProfile> {

    /** Approval states that cover a request; any other known state leaves it without a valid approval. */
    private static final Set<String> VALID_APPROVAL_STATUSES = Set.of("APPROVED", "GRANTED", "COMPLETED");

    @Override
    protected FrictionProfile doResolve(Map<String, Object> metadata, CanonicalSecurityContext context) {
        FrictionProfile existing = context.getFrictionProfile();
        Integer recentDeniedAccessCount = toInt(metadata.get("recentDeniedAccessCount"), metadata.get("recent_denied_access_count"));
        if (recentDeniedAccessCount == null && existing != null) {
            recentDeniedAccessCount = existing.getRecentDeniedAccessCount();
        }
        if (recentDeniedAccessCount == null && context.getObservedScope() != null) {
            recentDeniedAccessCount = context.getObservedScope().getRecentDeniedAccessCount();
        }

        // The business approval of the request only: a delegation's human approval is another fact (W2-9).
        Boolean approvalRequired = toBool(existing != null ? existing.getApprovalRequired() : null, metadata.get("approvalRequired"), metadata.get("approval_required"));
        String approvalStatus = text(existing != null ? existing.getApprovalStatus() : null, metadata.get("approvalStatus"), metadata.get("approval_status"));
        Boolean approvalGranted = toBool(existing != null ? existing.getApprovalGranted() : null, metadata.get("approvalGranted"), metadata.get("approval_granted"));
        if (approvalGranted == null && StringUtils.hasText(approvalStatus) && !isUnknownStatus(approvalStatus)) {
            approvalGranted = VALID_APPROVAL_STATUSES.contains(approvalStatus.trim().toUpperCase(Locale.ROOT));
        }
        Boolean approvalMissing = toBool(existing != null ? existing.getApprovalMissing() : null);
        if (approvalMissing == null) {
            approvalMissing = resolveApprovalMissing(approvalRequired, approvalGranted, approvalStatus);
        }

        Integer recentChallengeCount = toInt(metadata.get("recentChallengeCount"), metadata.get("recent_challenge_count"), metadata.get("challengeCount"));
        if (recentChallengeCount == null && existing != null) {
            recentChallengeCount = existing.getRecentChallengeCount();
        }
        if (recentChallengeCount == null && context.getSession() != null) {
            recentChallengeCount = context.getSession().getRecentChallengeCount();
        }
        Integer recentBlockCount = toInt(metadata.get("recentBlockCount"), metadata.get("recent_block_count"), metadata.get("blockCount"));
        if (recentBlockCount == null && existing != null) {
            recentBlockCount = existing.getRecentBlockCount();
        }
        if (recentBlockCount == null && context.getSession() != null) {
            recentBlockCount = context.getSession().getRecentBlockCount();
        }
        Integer recentEscalationCount = toInt(metadata.get("recentEscalationCount"), metadata.get("recent_escalation_count"), metadata.get("escalationCount"));
        if (recentEscalationCount == null && existing != null) {
            recentEscalationCount = existing.getRecentEscalationCount();
        }
        if (recentEscalationCount == null && context.getSession() != null) {
            recentEscalationCount = context.getSession().getRecentEscalationCount();
        }

        List<String> sessionActionEvidence = resolveSessionActionEvidence(metadata, context);
        if (recentChallengeCount == null) {
            recentChallengeCount = inferActionCount(sessionActionEvidence, "CHALLENGE", "MFA_COMPLETED", "MFA_REQUIRED");
        }
        if (recentBlockCount == null) {
            // A refused authorization is a denied access, not a Zero Trust block.
            recentBlockCount = inferActionCount(sessionActionEvidence, "BLOCK");
        }
        if (recentEscalationCount == null) {
            recentEscalationCount = inferActionCount(sessionActionEvidence, "ESCALATE", "ESCALATED");
        }
        if (recentDeniedAccessCount == null) {
            recentDeniedAccessCount = inferActionCount(sessionActionEvidence, "DENIED", "BLOCK", "ACCESS_DENIED");
        }

        FrictionProfile profile = FrictionProfile.builder()
                .summary(text(existing != null ? existing.getSummary() : null, metadata.get("frictionProfileSummary")))
                .recentChallengeCount(recentChallengeCount)
                .recentBlockCount(recentBlockCount)
                .recentEscalationCount(recentEscalationCount)
                .approvalRequired(approvalRequired)
                .approvalGranted(approvalGranted)
                .approvalMissing(approvalMissing)
                .approvalStatus(approvalStatus)
                .approvalLineage(strings(existing != null ? existing.getApprovalLineage() : null, metadata.get("approvalLineage"), metadata.get("approverLineage"), metadata.get("approval_lineage"), metadata.get("approverChain")))
                .pendingApproverRoles(strings(existing != null ? existing.getPendingApproverRoles() : null, metadata.get("pendingApproverRoles"), metadata.get("pending_approver_roles"), metadata.get("approverRoles")))
                .approvalTicketId(text(existing != null ? existing.getApprovalTicketId() : null, metadata.get("approvalTicketId"), metadata.get("approvalRequestId"), metadata.get("approval_request_id")))
                .approvalDecisionAgeMinutes(toInt(existing != null ? existing.getApprovalDecisionAgeMinutes() : null, metadata.get("approvalDecisionAgeMinutes"), metadata.get("approvalAgeMinutes"), metadata.get("approval_age_minutes")))
                .breakGlass(toBool(existing != null ? existing.getBreakGlass() : null, metadata.get("breakGlass"), metadata.get("break_glass"), metadata.get("breakGlassRequested")))
                .recentDeniedAccessCount(recentDeniedAccessCount)
                .blockedUser(toBool(existing != null ? existing.getBlockedUser() : null, metadata.get("blockedUser"), metadata.get("isBlockedUser"), metadata.get("blocked_user")))
                // The company records a host provider put in the profile are carried as they are (W2-6).
                .approvalRecords(existing != null && existing.getApprovalRecords() != null
                        ? new ArrayList<>(existing.getApprovalRecords()) : new ArrayList<>())
                .ticketRecords(existing != null && existing.getTicketRecords() != null
                        ? new ArrayList<>(existing.getTicketRecords()) : new ArrayList<>())
                .onCall(existing != null ? existing.getOnCall() : null)
                .travel(existing != null ? existing.getTravel() : null)
                .assignment(existing != null ? existing.getAssignment() : null)
                .accessHistory(existing != null ? existing.getAccessHistory() : null)
                .policies(existing != null && existing.getPolicies() != null
                        ? new ArrayList<>(existing.getPolicies()) : new ArrayList<>())
                .checkedRecordKinds(existing != null && existing.getCheckedRecordKinds() != null
                        ? new ArrayList<>(existing.getCheckedRecordKinds()) : new ArrayList<>())
                .build();
        alignWithRequestTime(profile, context, metadata);

        if (!StringUtils.hasText(profile.getSummary())) {
            profile.setSummary(doBuildSummary(profile, context));
        }

        return profile;
    }

    /**
     * With the host's approval or ticket records, the simple approval fields say what holds at the request time (W2-5):
     * a record decided after the request, outside its validity, for another target or beyond its limit (alone or with
     * what the session already exported under it) does not grant the request. The host's own verdict stays in the
     * records it gave; a host status that is not an approval word (PENDING) is kept.
     */
    private static void alignWithRequestTime(FrictionProfile profile, CanonicalSecurityContext context,
                                             Map<String, Object> metadata) {
        if (!CompanyRecordsEvaluator.hasRecords(profile)) {
            return;
        }
        CompanyRecordsEvaluator.Evaluation evaluation = CompanyRecordsEvaluator.evaluate(profile,
                CompanyRecordsEvaluator.Request.of(context,
                        SessionDecisionRecord.listOf(metadata.get(SessionDecisionRecord.METADATA_KEY))),
                EventTimeZone.get());
        Optional<RecordCheck> covering = evaluation.covering();
        // An approval nothing fails but whose use the engine cannot check is neither granted nor missing: the host's
        // status stays and the two lines are left unstated (P2 correction 3).
        if (covering.isEmpty() && evaluation.policy().satisfied() == null
                && evaluation.approvals().stream().anyMatch(RecordCheck::undecided)) {
            profile.setApprovalGranted(null);
            profile.setApprovalMissing(null);
            return;
        }
        profile.setApprovalGranted(covering.isPresent());
        String hostStatus = profile.getApprovalStatus();
        if (covering.isPresent()) {
            profile.setApprovalStatus("APPROVED");
            profile.setApprovalTicketId(covering.get().recordId());
        }
        else {
            if (!StringUtils.hasText(hostStatus)
                    || VALID_APPROVAL_STATUSES.contains(hostStatus.trim().toUpperCase(Locale.ROOT))) {
                profile.setApprovalStatus("NO_COVERING_APPROVAL");
            }
            // The ID of a record that does not cover the request is not the request's approval.
            boolean checkedRecord = evaluation.approvals().stream().anyMatch(check ->
                    check.recordId().equals(profile.getApprovalTicketId()))
                    || evaluation.tickets().stream().anyMatch(check -> check.recordId().equals(profile.getApprovalTicketId()));
            if (checkedRecord) {
                profile.setApprovalTicketId(null);
            }
        }
        Boolean satisfied = evaluation.policy().satisfied();
        if (satisfied != null) {
            profile.setApprovalMissing(!satisfied);
        }
        else if (profile.getApprovalRequired() != null) {
            profile.setApprovalMissing(profile.getApprovalRequired() && covering.isEmpty());
        }
    }

    @Override
    protected boolean doHasData(FrictionProfile profile) {
        return StringUtils.hasText(profile.getSummary())
                || profile.getRecentChallengeCount() != null
                || profile.getRecentBlockCount() != null
                || profile.getRecentEscalationCount() != null
                || profile.getApprovalRequired() != null
                || profile.getApprovalGranted() != null
                || profile.getApprovalMissing() != null
                || StringUtils.hasText(profile.getApprovalStatus())
                || !profile.getApprovalLineage().isEmpty()
                || !profile.getPendingApproverRoles().isEmpty()
                || StringUtils.hasText(profile.getApprovalTicketId())
                || profile.getApprovalDecisionAgeMinutes() != null
                || profile.getBreakGlass() != null
                || profile.getRecentDeniedAccessCount() != null
                || profile.getBlockedUser() != null
                || (profile.getApprovalRecords() != null && !profile.getApprovalRecords().isEmpty())
                || (profile.getTicketRecords() != null && !profile.getTicketRecords().isEmpty())
                || (profile.getPolicies() != null && !profile.getPolicies().isEmpty())
                || profile.getOnCall() != null
                || profile.getTravel() != null
                || profile.getAssignment() != null
                || profile.getAccessHistory() != null
                || (profile.getCheckedRecordKinds() != null && !profile.getCheckedRecordKinds().isEmpty());
    }

    @Override
    protected String doBuildSummary(FrictionProfile profile, CanonicalSecurityContext context) {
        List<String> facts = new ArrayList<>();
        if (profile.getRecentChallengeCount() != null) {
            facts.add("Recent challenges: " + profile.getRecentChallengeCount());
        }
        if (profile.getRecentBlockCount() != null) {
            facts.add("Recent blocks: " + profile.getRecentBlockCount());
        }
        if (profile.getApprovalRequired() != null) {
            facts.add("Approval required: " + profile.getApprovalRequired());
        }
        if (StringUtils.hasText(profile.getApprovalStatus())) {
            facts.add("Approval status: " + profile.getApprovalStatus());
        }
        if (!profile.getApprovalLineage().isEmpty()) {
            facts.add("Approval lineage: " + String.join(", ", profile.getApprovalLineage()));
        }
        if (!profile.getPendingApproverRoles().isEmpty()) {
            facts.add("Pending approver roles: " + String.join(", ", profile.getPendingApproverRoles()));
        }
        if (StringUtils.hasText(profile.getApprovalTicketId())) {
            facts.add("Approval ticket id: " + profile.getApprovalTicketId());
        }
        if (profile.getApprovalDecisionAgeMinutes() != null) {
            facts.add("Approval decision age minutes: " + profile.getApprovalDecisionAgeMinutes());
        }
        if (profile.getRecentDeniedAccessCount() != null) {
            facts.add("Recent denied access count: " + profile.getRecentDeniedAccessCount());
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    @Override
    public void apply(FrictionProfile profile, CanonicalSecurityContext context) {
        context.setFrictionProfile(profile);
    }


    /**
     * Whether no valid approval covers the request. Only a granted approval covers it; a rejected, pending, expired or
     * cancelled one does not. Null when the approval need or its state is unknown.
     */
    private Boolean resolveApprovalMissing(Boolean approvalRequired, Boolean approvalGranted, String approvalStatus) {
        if (Boolean.FALSE.equals(approvalRequired)) {
            return false;
        }
        if (!Boolean.TRUE.equals(approvalRequired)) {
            return null;
        }
        if (approvalGranted != null) {
            return !approvalGranted;
        }
        if (!StringUtils.hasText(approvalStatus)) {
            return true;
        }
        return null;
    }

    private static boolean isUnknownStatus(String approvalStatus) {
        return "UNKNOWN".equalsIgnoreCase(approvalStatus.trim());
    }

    private List<String> resolveSessionActionEvidence(Map<String, Object> metadata, CanonicalSecurityContext context) {
        CanonicalSecurityContext.SessionNarrativeProfile sessionNarrativeProfile =
                context != null ? context.getSessionNarrativeProfile() : null;
        if (sessionNarrativeProfile != null && !sessionNarrativeProfile.getSessionActionSequence().isEmpty()) {
            return sessionNarrativeProfile.getSessionActionSequence();
        }
        // A sequence: each repeated action is counted.
        return normalizeSequence(
                metadata.get("sessionActionSequence"),
                metadata.get("recentSessionActions"),
                metadata.get("sessionActions"));
    }

    private Integer inferActionCount(List<String> sessionActions, String... markers) {
        if (sessionActions == null || sessionActions.isEmpty()) {
            return null;
        }
        int count = 0;
        for (String sessionAction : sessionActions) {
            if (!StringUtils.hasText(sessionAction)) {
                continue;
            }
            String normalized = sessionAction.toUpperCase(Locale.ROOT);
            for (String marker : markers) {
                if (normalized.contains(marker)) {
                    count++;
                    break;
                }
            }
        }
        return count > 0 ? count : null;
    }
}
