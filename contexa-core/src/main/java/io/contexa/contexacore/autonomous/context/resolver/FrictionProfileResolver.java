package io.contexa.contexacore.autonomous.context.resolver;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static io.contexa.contexacore.autonomous.context.support.MetadataValueResolver.normalizeStrings;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;

/**
 * Resolves FrictionProfile from metadata.
 * Extracted from DefaultCanonicalSecurityContextProvider - all business logic preserved.
 */
public class FrictionProfileResolver extends AbstractProfileResolver<FrictionProfile> {

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

        Boolean approvalRequired = toBool(existing != null ? existing.getApprovalRequired() : null, metadata.get("approvalRequired"), metadata.get("approval_required"));
        if (approvalRequired == null && context.getDelegation() != null) {
            approvalRequired = context.getDelegation().getApprovalRequired();
        }
        String approvalStatus = text(existing != null ? existing.getApprovalStatus() : null, metadata.get("approvalStatus"), metadata.get("approval_status"));
        Boolean approvalGranted = toBool(existing != null ? existing.getApprovalGranted() : null, metadata.get("approvalGranted"), metadata.get("approval_granted"));
        if (approvalGranted == null && StringUtils.hasText(approvalStatus)) {
            approvalGranted = "APPROVED".equalsIgnoreCase(approvalStatus) || "GRANTED".equalsIgnoreCase(approvalStatus);
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
            recentBlockCount = inferActionCount(sessionActionEvidence, "BLOCK", "DENIED", "ACCESS_DENIED");
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
                .build();

        if (!StringUtils.hasText(profile.getSummary())) {
            profile.setSummary(doBuildSummary(profile, context));
        }

        return profile;
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
                || profile.getBlockedUser() != null;
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

    // --- Helper methods (moved from DefaultCanonicalSecurityContextProvider) ---

    private Boolean resolveApprovalMissing(Boolean approvalRequired, Boolean approvalGranted, String approvalStatus) {
        if (!Boolean.TRUE.equals(approvalRequired)) {
            return null;
        }
        if (Boolean.TRUE.equals(approvalGranted)) {
            return false;
        }
        if (!StringUtils.hasText(approvalStatus)) {
            return true;
        }
        return "MISSING".equalsIgnoreCase(approvalStatus) || "NOT_FOUND".equalsIgnoreCase(approvalStatus);
    }

    private List<String> resolveSessionActionEvidence(Map<String, Object> metadata, CanonicalSecurityContext context) {
        CanonicalSecurityContext.SessionNarrativeProfile sessionNarrativeProfile =
                context != null ? context.getSessionNarrativeProfile() : null;
        if (sessionNarrativeProfile != null && !sessionNarrativeProfile.getSessionActionSequence().isEmpty()) {
            return sessionNarrativeProfile.getSessionActionSequence();
        }
        return normalizeStrings(
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
