package io.contexa.showcase.workload.contexa.context;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.enricher.FrictionContextProvider;
import io.contexa.showcase.business.context.BusinessContextLookup;
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
            Instant at = event.getTimestamp() == null ? Instant.now() : event.getTimestamp().toInstant(ZoneOffset.UTC);
            apply(context, facts(rule.get().operation(), event.getUserId(), path, text(metadata.get("queryString")),
                    event.getSourceIp(), at));
        } catch (RuntimeException e) {
            log.error("Business context lookup failed: userId={}, path={}", event.getUserId(), path, e);
            apply(context, new Facts(List.of("Business context lookup failed; the company facts of this request are "
                    + "unknown."), null, null, null));
        }
    }

    record Facts(List<String> lines, ApprovalCoverage approval, TicketCoverage ticket, Instant at) {
    }

    private Facts facts(BusinessOperation operation, String username, String path, String query, String clientIp,
                        Instant at) {
        String[] segments = path.split("/");
        String target = segments.length > 3 ? segments[3] : null;
        List<String> lines = new ArrayList<>();
        switch (operation) {
            case EXPORT, EXPORT_STREAM -> {
                int items = items(query);
                AssignmentStatus assigned = lookup.projectAssigned(username, target, at);
                ApprovalCoverage approval = lookup.approvalExists(username, target, items, at);
                TicketCoverage ticket = lookup.ticketCovers(username, target, operation, at);
                OncallStatus oncall = lookup.oncallHas(username, at);
                AccessHistory history = lookup.historyDays(username, target, at, 30);
                lines.add(VERIFIED + "requester assigned to project " + target + ": " + yesNo(assigned.assigned()));
                lines.add(VERIFIED + approvalLine(approval, items));
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
                lines.add(SCOPE_NOTE);
                return new Facts(lines, approval, ticket, at);
            }
            case DOCUMENT_READ, DOCUMENT_DOWNLOAD -> {
                String project = projectOfDocument(target);
                if (project == null) {
                    return new Facts(List.of(VERIFIED + "document " + target + " does not exist."), null, null, at);
                }
                AssignmentStatus assigned = lookup.projectAssigned(username, project, at);
                TicketCoverage ticket = lookup.ticketCovers(username, project, operation, at);
                AccessHistory history = lookup.historyDays(username, project, at, 90);
                lines.add(VERIFIED + "requester assigned to project " + project + ": " + yesNo(assigned.assigned()));
                lines.add(VERIFIED + ticketLine(ticket));
                lines.add(VERIFIED + historyLine(history, project));
                lines.add(VERIFIED + networkLine(lookup.networkContext(username, clientIp, at)));
                lines.add(SCOPE_NOTE);
                return new Facts(lines, null, ticket, at);
            }
            case ROLE_GRANT -> {
                String project = parameter(query, "project");
                String grantee = parameter(query, "grantee");
                TicketCoverage ticket = lookup.ticketCovers(username, project, operation, at);
                lines.add(VERIFIED + "the request gives employee " + grantee + " a role on project " + project + ".");
                lines.add(VERIFIED + changeTicketLine(ticket));
                lines.add(VERIFIED + networkLine(lookup.networkContext(username, clientIp, at)));
                lines.add(SCOPE_NOTE);
                return new Facts(lines, null, ticket, at);
            }
            case CUSTOMER_READ -> {
                CustomerOwnership ownership = lookup.customerOwner(username, target);
                lines.add(VERIFIED + "requester is the account manager of customer " + target + ": "
                        + yesNo(ownership.owner()));
                if (ownership.projectKey() != null) {
                    lines.add(VERIFIED + ticketLine(lookup.ticketCovers(username, ownership.projectKey(), operation, at)));
                }
                lines.add(VERIFIED + networkLine(lookup.networkContext(username, clientIp, at)));
                lines.add(SCOPE_NOTE);
                return new Facts(lines, null, null, at);
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
        if (facts.approval() != null) {
            profile.setApprovalGranted(facts.approval().covered());
            profile.setApprovalStatus(facts.approval().covered() ? "APPROVED" : "NO_COVERING_APPROVAL");
            if (facts.approval().covered()) {
                profile.setApprovalTicketId(facts.approval().approvalKey());
                if (facts.approval().validFrom() != null && facts.at() != null) {
                    profile.setApprovalDecisionAgeMinutes((int) Math.max(0,
                            Duration.between(facts.approval().validFrom(), facts.at()).toMinutes()));
                }
            }
        }
        profile.setSummary("Company facts of this request were looked up in the business database.");
    }

    static String approvalLine(ApprovalCoverage approval, int items) {
        if (approval.covered()) {
            return "approval " + approval.approvalKey() + " by " + approval.approver() + " for purpose "
                    + approval.purpose() + " covers up to " + approval.maxItems() + " items (requested " + items
                    + "), valid " + approval.validFrom() + " to " + approval.validUntil() + ".";
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

    private static int items(String query) {
        if (query == null) {
            return 1;
        }
        for (String pair : query.split("&")) {
            if (pair.startsWith("items=")) {
                try {
                    return Integer.parseInt(pair.substring("items=".length()));
                } catch (NumberFormatException e) {
                    return 1;
                }
            }
        }
        return 1;
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
