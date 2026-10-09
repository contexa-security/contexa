package io.contexa.showcase.workload.contexa.context;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.enricher.FrictionContextProvider;
import io.contexa.showcase.business.context.AccessApprovalPolicy;
import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.context.ExportApprovalPolicy;
import io.contexa.showcase.business.context.BusinessContextLookup.AccessHistory;
import io.contexa.showcase.business.context.BusinessContextLookup.ApprovalCoverage;
import io.contexa.showcase.business.context.BusinessContextLookup.AssignmentStatus;
import io.contexa.showcase.business.context.BusinessContextLookup.ClaimCheck;
import io.contexa.showcase.business.context.BusinessContextLookup.NetworkContext;
import io.contexa.showcase.business.context.BusinessContextLookup.CustomerOwnership;
import io.contexa.showcase.business.context.BusinessContextLookup.OncallStatus;
import io.contexa.showcase.business.context.BusinessContextLookup.RunPrincipal;
import io.contexa.showcase.business.context.BusinessContextLookup.TicketCoverage;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.business.work.RbacPolicy;
import io.contexa.showcase.business.work.WorkDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Puts the company facts of a request into the engine's friction and approval context, read through the same
 * {@link BusinessContextLookup} control C2 uses (deck p.7, p.18; P1-BE-04). Every line says it was verified by the
 * business database. The facts describe the request only; this provider never decides and never writes a rule's
 * conclusion such as "approval required".
 * <p>
 * The engine swallows provider failures with a warning, so a failed lookup is written into the context as such and
 * logged as an error here (reuse-assets 2.4).
 */
public class BusinessFrictionProvider implements FrictionContextProvider {

    private static final Logger log = LoggerFactory.getLogger(BusinessFrictionProvider.class);

    static final String VERIFIED = "Verified by the business database (" + BusinessContextLookup.SOURCE + "): ";
    static final String SCOPE_NOTE = "These facts describe this request only; they are not authentication, MFA "
            + "completion or a security action release.";
    /** A requester's own statement is shown apart from the verified facts (deck A8: a claim is not evidence). */
    static final String CLAIMED = "Requester claim in the request (not verified): ";

    private final BusinessContextLookup lookup;
    private final WorkDatabase database;

    public BusinessFrictionProvider(BusinessContextLookup lookup, WorkDatabase database) {
        this.lookup = lookup;
        this.database = database;
    }

    @Override
    public void enrich(SecurityEvent event, CanonicalSecurityContext context) {
        if (event == null || event.getUserId() == null || event.getMetadata() == null) {
            return;
        }
        Map<String, Object> metadata = event.getMetadata();
        String path = text(metadata.get("requestPath"));
        String method = text(metadata.get("httpMethod"));
        if (path == null || method == null) {
            return;
        }
        Optional<RbacPolicy.Rule> rule = RbacPolicy.match(method, path);
        if (rule.isEmpty()) {
            return;
        }
        try {
            Optional<RunPrincipal> principal = lookup.principal(event.getUserId());
            if (principal.isEmpty()) {
                return;
            }
            if (event.getTimestamp() == null) {
                // The company facts depend on the request time; without it nothing is looked up (survey D3).
                apply(context, Facts.notLookedUp("The request time is unknown; the company facts of this request, "
                        + "which depend on it, were not looked up."));
                return;
            }
            Instant at = event.getTimestamp().toInstant(ZoneOffset.UTC);
            apply(context, facts(rule.get().operation(), event.getUserId(), path, text(metadata.get("queryString")),
                    event.getSourceIp(), at));
        } catch (RuntimeException e) {
            log.error("Business context lookup failed: userId={}, path={}", event.getUserId(), path, e);
            apply(context, Facts.notLookedUp("Business context lookup failed; the company facts of this request are "
                    + "unknown."));
        }
    }

    /**
     * @param approval         the approval record of an export; null for the other operations, whose approval record
     *                         is a ticket that covers the request (Q-A4)
     * @param approvalRequired whether the company requires an approval for this request, by the same policy row the
     *                         business-record control applies (ContextLookupRules): the export rule (H-15) or the
     *                         access rule of role grants, customers and documents (Q-A4); null when no rule applies
     * @param lookedUp         whether the business database was read for these facts (survey D2)
     */
    record Facts(List<String> lines, ApprovalCoverage approval, TicketCoverage ticket, Instant at,
                 Boolean approvalRequired, boolean lookedUp) {

        Facts(List<String> lines, ApprovalCoverage approval, TicketCoverage ticket, Instant at,
              Boolean approvalRequired) {
            this(lines, approval, ticket, at, approvalRequired, true);
        }

        Facts(List<String> lines, ApprovalCoverage approval, TicketCoverage ticket, Instant at) {
            this(lines, approval, ticket, at, null, true);
        }

        static Facts notLookedUp(String line) {
            return new Facts(List.of(line), null, null, null, null, false);
        }
    }

    private Facts facts(BusinessOperation operation, String username, String path, String query, String clientIp,
                        Instant at) {
        String[] segments = path.split("/");
        String target = segments.length > 3 ? segments[3] : null;
        List<String> lines = new ArrayList<>();
        switch (operation) {
            case EXPORT, EXPORT_STREAM, EXPORT_ASYNC -> {
                Integer items = items(query);
                if (items == null) {
                    // Control C2 refuses such an export without looking anything up; the engine is told the same.
                    return Facts.notLookedUp("The export names no valid item count; its company facts were not "
                            + "looked up.");
                }
                AssignmentStatus assigned = lookup.projectAssigned(username, target, at);
                ApprovalCoverage approval = lookup.approvalExists(username, target, items, at);
                TicketCoverage ticket = lookup.ticketCovers(username, target, operation, at);
                OncallStatus oncall = lookup.oncallHas(username, at);
                AccessHistory history = lookup.historyDays(username, target, at, 30);
                ExportApprovalPolicy policy = lookup.exportApprovalPolicy();
                boolean required = policy.requiresApproval(assigned.assigned(), items, ticket.covered(),
                        oncall.onCall());
                lines.add(VERIFIED + "requester assigned to project " + target + ": " + yesNo(assigned.assigned()));
                lines.add(VERIFIED + approvalLine(approval, items, at));
                lines.add(VERIFIED + ticketLine(ticket));
                lines.add(VERIFIED + oncallLine(oncall));
                lines.add(VERIFIED + historyLine(history, target));
                String claimed = parameter(query, "claimedTicket");
                if (claimed != null) {
                    ClaimCheck claim = lookup.claimedTicket(username, claimed, target, operation, at);
                    lines.add(CLAIMED + "ticket " + claimed + " covers this request");
                    lines.add(VERIFIED + claimLine(claim));
                }
                lines.add(VERIFIED + networkLine(lookup.networkContext(username, clientIp, at)));
                lines.add(VERIFIED + policyLine(policy, required));
                lines.add(SCOPE_NOTE);
                return new Facts(lines, approval, ticket, at, required);
            }
            case DOCUMENT_READ, DOCUMENT_DOWNLOAD -> {
                String project = projectOfDocument(target);
                if (project == null) {
                    return new Facts(List.of(VERIFIED + "document " + target + " does not exist."), null, null, at);
                }
                AccessApprovalPolicy policy = lookup.accessApprovalPolicy(operation);
                int window = policy.recentWorkDays() != null ? policy.recentWorkDays() : 90;
                AssignmentStatus assigned = lookup.projectAssigned(username, project, at);
                TicketCoverage ticket = lookup.ticketCovers(username, project, operation, at);
                AccessHistory history = lookup.historyDays(username, project, at, window);
                boolean required = policy.requiresApproval(false, assigned.assigned(), history.days());
                lines.add(VERIFIED + "requester assigned to project " + project + ": " + yesNo(assigned.assigned()));
                lines.add(VERIFIED + ticketLine(ticket));
                lines.add(VERIFIED + historyLine(history, project));
                lines.add(VERIFIED + networkLine(lookup.networkContext(username, clientIp, at)));
                lines.add(VERIFIED + accessPolicyLine(policy, required));
                lines.add(SCOPE_NOTE);
                return new Facts(lines, null, ticket, at, required);
            }
            case ROLE_GRANT -> {
                String project = parameter(query, "project");
                String grantee = parameter(query, "grantee");
                AccessApprovalPolicy policy = lookup.accessApprovalPolicy(operation);
                TicketCoverage ticket = lookup.ticketCovers(username, project, operation, at);
                boolean required = policy.requiresApproval(false, false, 0);
                lines.add(VERIFIED + "the request gives employee " + grantee + " a role on project " + project + ".");
                lines.add(VERIFIED + changeTicketLine(ticket));
                lines.add(VERIFIED + networkLine(lookup.networkContext(username, clientIp, at)));
                lines.add(VERIFIED + accessPolicyLine(policy, required));
                lines.add(SCOPE_NOTE);
                return new Facts(lines, null, ticket, at, required);
            }
            case CUSTOMER_READ -> {
                AccessApprovalPolicy policy = lookup.accessApprovalPolicy(operation);
                CustomerOwnership ownership = lookup.customerOwner(username, target);
                TicketCoverage ticket = ownership.projectKey() == null ? null
                        : lookup.ticketCovers(username, ownership.projectKey(), operation, at);
                boolean required = policy.requiresApproval(ownership.owner(), false, 0);
                lines.add(VERIFIED + "requester is the account manager of customer " + target + ": "
                        + yesNo(ownership.owner()));
                if (ticket != null) {
                    lines.add(VERIFIED + ticketLine(ticket));
                }
                lines.add(VERIFIED + networkLine(lookup.networkContext(username, clientIp, at)));
                lines.add(VERIFIED + accessPolicyLine(policy, required));
                lines.add(SCOPE_NOTE);
                return new Facts(lines, null, ticket, at, required);
            }
            default -> {
                return new Facts(List.of(), null, null, at);
            }
        }
    }

    private static void apply(CanonicalSecurityContext context, Facts facts) {
        if (facts.lines().isEmpty()) {
            return;
        }
        FrictionProfile profile = context.getFrictionProfile();
        if (profile == null) {
            profile = new FrictionProfile();
            context.setFrictionProfile(profile);
        }
        List<String> lineage = new ArrayList<>(profile.getApprovalLineage() == null ? List.of()
                : profile.getApprovalLineage());
        lineage.addAll(facts.lines());
        profile.setApprovalLineage(lineage);
        if (facts.approval() == null && facts.approvalRequired() != null) {
            // A ticket that covers the request is the approval record of the company's access rules (Q-A4).
            boolean covered = facts.ticket() != null && facts.ticket().covered();
            profile.setApprovalRequired(facts.approvalRequired());
            profile.setApprovalMissing(facts.approvalRequired() && !covered);
            if (covered || facts.approvalRequired()) {
                profile.setApprovalGranted(covered);
                profile.setApprovalStatus(covered ? "APPROVED" : "NO_COVERING_APPROVAL");
            }
            if (covered) {
                profile.setApprovalTicketId(facts.ticket().ticketKey());
            }
        }
        if (facts.approval() != null) {
            profile.setApprovalGranted(facts.approval().covered());
            profile.setApprovalStatus(facts.approval().covered() ? "APPROVED" : "NO_COVERING_APPROVAL");
            if (facts.approvalRequired() != null) {
                profile.setApprovalRequired(facts.approvalRequired());
                profile.setApprovalMissing(facts.approvalRequired() && !facts.approval().covered());
            }
            if (facts.approval().covered()) {
                profile.setApprovalTicketId(facts.approval().approvalKey());
                // Only a recorded decision time gives a decision age; the start of validity is not one (survey D5).
                // A decision recorded after the request has no age at the request time: the approval line states
                // when it was recorded instead of an age clipped to zero (W2-5, case S12).
                if (facts.approval().approvedAt() != null && facts.at() != null
                        && !facts.approval().approvedAt().isAfter(facts.at())) {
                    profile.setApprovalDecisionAgeMinutes((int) Duration.between(facts.approval().approvedAt(),
                            facts.at()).toMinutes());
                }
            }
        }
        profile.setSummary(facts.lookedUp() ? "Company facts of this request were looked up in the business database."
                : "Company facts of this request were not looked up in the business database.");
    }

    /** The company's export approval policy and whether it requires an approval here, as the policy row states it. */
    /** The company's access rule and whether it requires an approval for this request (Q-A4). */
    static String accessPolicyLine(AccessApprovalPolicy policy, boolean required) {
        return "company policy " + policy.policyKey() + " (" + policy.description()
                + ") requires an approval for this request: " + yesNo(required);
    }

    static String policyLine(ExportApprovalPolicy policy, boolean required) {
        return "company policy " + policy.policyKey() + " (" + policy.description() + " Assigned export limit: "
                + policy.assignedExportLimit() + " items.) requires an approval for this export: " + yesNo(required);
    }

    static String approvalLine(ApprovalCoverage approval, int items) {
        return approvalLine(approval, items, null);
    }

    /**
     * The covering approval as the record states it, with when its decision was recorded when the record says so: a
     * decision recorded after the request is stated as such, with the minutes between them (W2-5, case S12).
     */
    static String approvalLine(ApprovalCoverage approval, int items, Instant at) {
        if (approval.covered()) {
            String line = "approval " + approval.approvalKey() + " by " + approval.approver() + " for purpose "
                    + approval.purpose() + " covers up to " + approval.maxItems() + " items (requested " + items
                    + "), valid " + approval.validFrom() + " to " + approval.validUntil() + ".";
            Instant decided = approval.approvedAt();
            if (decided == null || at == null) {
                return line;
            }
            if (!decided.isAfter(at)) {
                return line + " Its decision was recorded at " + decided + ", before this request.";
            }
            return line + " Its decision was recorded at " + decided + ", "
                    + Duration.between(at, decided).toMinutes() + " minutes after this request"
                    + (approval.validFrom() != null && approval.validFrom().isBefore(decided)
                    ? ", with a validity that starts before the decision was recorded." : ".");
        }
        if (approval.approvalKey() == null) {
            return "no approval of the requester exists for this project.";
        }
        return "closest approval " + approval.approvalKey() + " does not cover this request: "
                + String.join(", ", approval.mismatches()) + ".";
    }

    static String ticketLine(TicketCoverage ticket) {
        if (ticket.covered()) {
            return "ITSM ticket " + ticket.ticketKey() + " approved by " + ticket.approver() + " for purpose "
                    + ticket.purpose() + " covers this request, valid " + ticket.validFrom() + " to "
                    + ticket.validUntil() + ".";
        }
        if (ticket.ticketKey() == null) {
            return "no ITSM ticket of the requester exists.";
        }
        return "closest ITSM ticket " + ticket.ticketKey() + " does not fit this request: "
                + String.join(", ", ticket.mismatches()) + ".";
    }

    static String oncallLine(OncallStatus oncall) {
        return oncall.onCall()
                ? "requester is on call (" + oncall.team() + ") until " + oncall.endsAt() + "."
                : "requester is not on call at the request time.";
    }

    static String historyLine(AccessHistory history, String project) {
        return "days with access to project " + project + " in the last " + history.windowDays() + " days: "
                + history.days() + (history.lastAccessDate() == null ? "; never accessed in that window."
                : "; last access on " + history.lastAccessDate() + ".");
    }

    private String projectOfDocument(String documentKey) {
        if (documentKey == null) {
            return null;
        }
        return database.jdbc().queryForList("select project_key from document where document_key = :key",
                new MapSqlParameterSource("key", documentKey), String.class).stream().findFirst().orElse(null);
    }

    /** The export's item count; null when the request names none or an invalid one (survey D4). */
    static Integer items(String query) {
        if (query == null) {
            return null;
        }
        for (String pair : query.split("&")) {
            if (pair.startsWith("items=")) {
                try {
                    int items = Integer.parseInt(pair.substring("items=".length()).trim());
                    return items > 0 ? items : null;
                } catch (NumberFormatException e) {
                    return null;
                }
            }
        }
        return null;
    }

    private static String yesNo(boolean value) {
        return value ? "yes" : "no";
    }

    static String changeTicketLine(TicketCoverage ticket) {
        if (ticket.covered()) {
            return "an approved change ticket " + ticket.ticketKey() + " covers this grant.";
        }
        return ticket.ticketKey() == null ? "no change ticket of the requester exists."
                : "no change ticket covers this grant; the closest, " + ticket.ticketKey() + ", fails on "
                + String.join(", ", ticket.mismatches()) + ".";
    }

    static String networkLine(NetworkContext network) {
        return switch (network.kind()) {
            case OFFICE -> "request network " + network.network() + " is a company office network.";
            case TRAVEL -> "request network " + network.network() + " belongs to the requester's registered business "
                    + "trip " + network.planKey() + " (" + network.city() + ", " + network.country() + ").";
            case EXTERNAL -> "the request address is not in a company office network and no registered business "
                    + "trip of the requester covers it.";
            case UNKNOWN -> "the request network is unknown.";
        };
    }

    static String claimLine(ClaimCheck claim) {
        if (!claim.exists()) {
            return "the claimed ticket " + claim.ticketKey() + " does not exist for the requester.";
        }
        if (claim.confirmed()) {
            return "the claimed ticket " + claim.ticketKey() + " exists and covers this request.";
        }
        return "the claimed ticket " + claim.ticketKey() + " exists but does not cover this request ("
                + String.join(", ", claim.coverage().mismatches()) + ").";
    }

    /** A query parameter value; parameters are URL-encoded by the client, and ticket keys need no decoding. */
    static String parameter(String query, String name) {
        if (query == null) {
            return null;
        }
        for (String pair : query.split("&")) {
            if (pair.startsWith(name + "=") && pair.length() > name.length() + 1) {
                return pair.substring(name.length() + 1);
            }
        }
        return null;
    }

    private static String text(Object value) {
        return value == null ? null : value.toString();
    }
}
