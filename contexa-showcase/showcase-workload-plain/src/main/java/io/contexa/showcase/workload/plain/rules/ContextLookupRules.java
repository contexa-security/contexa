package io.contexa.showcase.workload.plain.rules;

import io.contexa.showcase.business.context.AccessApprovalPolicy;
import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.context.ExportApprovalPolicy;
import io.contexa.showcase.business.context.BusinessContextLookup.AccessHistory;
import io.contexa.showcase.business.context.BusinessContextLookup.ApprovalCoverage;
import io.contexa.showcase.business.context.BusinessContextLookup.ClaimCheck;
import io.contexa.showcase.business.context.BusinessContextLookup.NetworkContext;
import io.contexa.showcase.business.context.BusinessContextLookup.NetworkKind;
import io.contexa.showcase.business.context.BusinessContextLookup.AssignmentStatus;
import io.contexa.showcase.business.context.BusinessContextLookup.CustomerOwnership;
import io.contexa.showcase.business.context.BusinessContextLookup.OncallStatus;
import io.contexa.showcase.business.context.BusinessContextLookup.TicketCoverage;
import io.contexa.showcase.business.work.BusinessOperation;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Control C2, context lookup rules over the same lookups control D reads (deck p.18: ticket.covers, oncall.has,
 * project.assigned, approval.exists, history.days, and the request network). Draft rules of ADR-22, frozen with a
 * hash before the P2 recordings. Every planned lookup runs before a rule decides, so the recorded facts are complete.
 */
public class ContextLookupRules {

    /** Window of the access history looked up when the company's document rule sets none (it sets 90, Q-A4). */
    public static final int HISTORY_WINDOW_DAYS = 90;

    /** Window of the access history looked up for exports; recorded with the decision, not used by the rule. */
    public static final int EXPORT_HISTORY_WINDOW_DAYS = 30;

    private final BusinessContextLookup lookup;

    public ContextLookupRules(BusinessContextLookup lookup) {
        this.lookup = lookup;
    }

    public RuleDecision evaluate(RequestFacts request) {
        return evaluate(request, RuleSettings.FROZEN);
    }

    /**
     * The decision under the given settings: the frozen ones for every live request, a visitor's own in the rules
     * scene over the facts a run recorded (H-10). A setting that is off only removes the reason it lets a request
     * through or refuses it; every lookup still runs, so the recorded facts stay complete.
     */
    public RuleDecision evaluate(RequestFacts request, RuleSettings settings) {
        return switch (request.operation()) {
            case PROJECT_LIST -> RuleDecision.allow("C2-PASS", "Project list needs no business context", Map.of());
            case EXPORT, EXPORT_STREAM, EXPORT_ASYNC -> export(request, settings);
            case DOCUMENT_READ, DOCUMENT_DOWNLOAD -> singleDocument(request, settings);
            case CUSTOMER_READ -> customer(request, settings);
            case ROLE_GRANT -> grant(request, settings);
        };
    }

    private RuleDecision export(RequestFacts request, RuleSettings settings) {
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("projectKey", request.projectKey());
        facts.put("items", request.items());
        if (request.items() == null) {
            // Without an item count no approval or policy can be checked; control D looks nothing up either.
            return RuleDecision.deny("C2-ITEMS-UNKNOWN", "The export names no valid item count", facts);
        }
        ApprovalCoverage approval = lookup.approvalExists(request.username(), request.projectKey(), request.items(),
                request.companyTime());
        TicketCoverage ticket = lookup.ticketCovers(request.username(), request.projectKey(), request.operation(),
                request.companyTime());
        OncallStatus oncall = lookup.oncallHas(request.username(), request.companyTime());
        AssignmentStatus assigned = lookup.projectAssigned(request.username(), request.projectKey(),
                request.companyTime());
        AccessHistory history = lookup.historyDays(request.username(), request.projectKey(), request.companyTime(),
                EXPORT_HISTORY_WINDOW_DAYS);
        // The company's own approval policy row, the same one control D tells the engine about (H-15).
        ExportApprovalPolicy policy = lookup.exportApprovalPolicy();
        facts.put("policy", policy);
        facts.put("approval", approval);
        facts.put("ticket", ticket);
        facts.put("oncall", oncall);
        facts.put("assigned", assigned);
        facts.put("accessDaysLast30", history.days());
        NetworkContext network = network(request, facts);
        if (request.claimedTicket() != null) {
            ClaimCheck claim = lookup.claimedTicket(request.username(), request.claimedTicket(), request.projectKey(),
                    request.operation(), request.companyTime());
            facts.put("claim", claim);
            if (settings.falseClaim() && !claim.confirmed()) {
                return RuleDecision.deny("C2-FALSE-CLAIM", "The ticket named in the request does not cover it", facts);
            }
        }
        if (settings.external() && network.kind() == NetworkKind.EXTERNAL) {
            return external(facts);
        }
        if (settings.approval() && approval.covered()) {
            return RuleDecision.allow("C2-APPROVAL", "An approval covers the project and the item count", facts);
        }
        // The company's policy row decides; a visitor's limit replaces only its assigned export limit.
        ExportApprovalPolicy effective = settings.assignedLimit() == null ? policy : new ExportApprovalPolicy(
                policy.policyKey(), policy.description(), settings.assignedLimit(), policy.ticketAndOncallExempt());
        boolean ticketCovered = settings.ticket() && ticket.covered();
        boolean assignedToProject = settings.assigned() && assigned.assigned();
        if (!effective.requiresApproval(assignedToProject, request.items(), ticketCovered, oncall.onCall())) {
            if (effective.ticketAndOncallExempt() && ticketCovered && oncall.onCall()) {
                return RuleDecision.allow("C2-TICKET-ONCALL", "A fitting ticket and the requester is on call", facts);
            }
            return RuleDecision.allow("C2-ASSIGNED", "Assigned to the project and at most "
                    + effective.assignedExportLimit() + " items", facts);
        }
        return RuleDecision.deny("C2-NO-CONTEXT", "No fitting approval or on-call ticket", facts);
    }

    private RuleDecision singleDocument(RequestFacts request, RuleSettings settings) {
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("projectKey", request.projectKey());
        // The company's own document access rule, the same row control D tells the engine about (Q-A4).
        AccessApprovalPolicy policy = lookup.accessApprovalPolicy(request.operation());
        int window = policy.recentWorkDays() != null ? policy.recentWorkDays() : HISTORY_WINDOW_DAYS;
        AssignmentStatus assigned = lookup.projectAssigned(request.username(), request.projectKey(),
                request.companyTime());
        TicketCoverage ticket = lookup.ticketCovers(request.username(), request.projectKey(), request.operation(),
                request.companyTime());
        AccessHistory history = lookup.historyDays(request.username(), request.projectKey(), request.companyTime(),
                window);
        facts.put("policy", policy);
        facts.put("assigned", assigned);
        facts.put("ticket", ticket);
        facts.put("accessDaysLast" + window, history.days());
        if (network(request, facts).kind() == NetworkKind.EXTERNAL && settings.external()) {
            return external(facts);
        }
        boolean assignedToProject = settings.assigned() && assigned.assigned();
        if (policy.assignedExempt() && assignedToProject) {
            return RuleDecision.allow("C2-ASSIGNED", "Assigned to the project", facts);
        }
        if (settings.ticket() && ticket.covered()) {
            return RuleDecision.allow("C2-TICKET", "A fitting ticket covers the project", facts);
        }
        if (settings.history() && !policy.requiresApproval(false, assignedToProject, history.days())) {
            return RuleDecision.allow("C2-HISTORY", "Worked on the project in the last " + window + " days", facts);
        }
        return RuleDecision.deny("C2-NO-CONTEXT", "Not assigned, no fitting ticket, no recent work on the project",
                facts);
    }

    private RuleDecision customer(RequestFacts request, RuleSettings settings) {
        Map<String, Object> facts = new LinkedHashMap<>();
        AccessApprovalPolicy policy = lookup.accessApprovalPolicy(request.operation());
        facts.put("policy", policy);
        CustomerOwnership ownership = lookup.customerOwner(request.username(), request.targetKey());
        facts.put("customer", ownership);
        TicketCoverage ticket = ownership.projectKey() == null ? null : lookup.ticketCovers(request.username(),
                ownership.projectKey(), BusinessOperation.CUSTOMER_READ, request.companyTime());
        facts.put("ticket", ticket);
        if (network(request, facts).kind() == NetworkKind.EXTERNAL && settings.external()) {
            return external(facts);
        }
        if (settings.assigned() && !policy.requiresApproval(ownership.owner(), false, 0)) {
            return RuleDecision.allow("C2-ACCOUNT", "Account manager of the customer", facts);
        }
        if (settings.ticket() && ticket != null && ticket.covered()) {
            return RuleDecision.allow("C2-TICKET", "A fitting ticket covers the customer's project", facts);
        }
        return RuleDecision.deny("C2-NO-CONTEXT", "Not the account manager and no fitting ticket", facts);
    }

    /** Deck A5: a role is given only under an approved change ticket for that project. */
    private RuleDecision grant(RequestFacts request, RuleSettings settings) {
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("projectKey", request.projectKey());
        facts.put("grantee", request.targetKey());
        AccessApprovalPolicy policy = lookup.accessApprovalPolicy(request.operation());
        facts.put("policy", policy);
        TicketCoverage ticket = lookup.ticketCovers(request.username(), request.projectKey(), request.operation(),
                request.companyTime());
        facts.put("ticket", ticket);
        if (network(request, facts).kind() == NetworkKind.EXTERNAL && settings.external()) {
            return external(facts);
        }
        if (!policy.requiresApproval(false, false, 0)) {
            return RuleDecision.allow("C2-NO-APPROVAL-NEEDED", "The company's grant rule needs no approval", facts);
        }
        if (settings.ticket() && ticket.covered()) {
            return RuleDecision.allow("C2-CHANGE-TICKET", "An approved change ticket covers the grant", facts);
        }
        return RuleDecision.deny("C2-NO-CHANGE-TICKET", "No approved change ticket covers the grant", facts);
    }

    private NetworkContext network(RequestFacts request, Map<String, Object> facts) {
        NetworkContext network = lookup.networkContext(request.username(), request.clientIp(), request.companyTime());
        facts.put("network", network);
        return network;
    }

    /** Company data is used from company offices or a registered business trip only (deck A1). */
    private static RuleDecision external(Map<String, Object> facts) {
        return RuleDecision.deny("C2-EXTERNAL-NETWORK",
                "Not a company office network and no registered business trip covers it", facts);
    }
}
