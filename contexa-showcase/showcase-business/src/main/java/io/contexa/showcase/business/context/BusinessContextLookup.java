package io.contexa.showcase.business.context;

import io.contexa.showcase.business.work.BusinessOperation;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * The company facts both context-aware controls read: the lookup rules of control C2 and the context providers of
 * control D call the same implementation over the same source (deck p.7, p.18, p.23; P1-BE-04). Every answer says
 * which source row decided it, so a decision can show "verified by the business database".
 * <p>
 * Lookups take the sign-in name of a run principal; a run overlay (facts chosen for that run) is visible only to
 * the principals of that run.
 */
public interface BusinessContextLookup {

    /** Source label used in every answer: facts come from the business database, not from the requester. */
    String SOURCE = "showcase_work";

    Optional<RunPrincipal> principal(String username);

    /** deck {@code ticket.covers}: an ITSM ticket whose requester, approver, target, purpose and validity all fit. */
    TicketCoverage ticketCovers(String username, String projectKey, BusinessOperation operation, Instant at);

    /** deck {@code oncall.has}: the employee is on call at that company time. */
    OncallStatus oncallHas(String username, Instant at);

    /** deck {@code project.assigned}: the employee is assigned to the project on that day. */
    AssignmentStatus projectAssigned(String username, String projectKey, Instant at);

    /** deck {@code approval.exists}: an approved request covers the project, the item count and the time. */
    ApprovalCoverage approvalExists(String username, String projectKey, int items, Instant at);

    /** deck {@code history.days}: days with access to the project within the window before that day. */
    AccessHistory historyDays(String username, String projectKey, Instant at, int windowDays);

    /** Whether the employee is the account manager of the customer. */
    CustomerOwnership customerOwner(String username, String customerKey);

    /**
     * Checks a ticket the requester names in the request (deck A8: a claimed ticket is not evidence until the business
     * database confirms it): whether it exists for this requester and whether it covers the request.
     */
    ClaimCheck claimedTicket(String username, String ticketKey, String projectKey, BusinessOperation operation,
                             Instant at);

    /**
     * Where the request comes from in company terms (deck A1): a company office network, a network of the requester's
     * registered business trip at that time, or neither.
     */
    NetworkContext networkContext(String username, String clientIp, Instant at);

    record RunPrincipal(String username, String runId, String employeeKey, String roleKey, String organizationId,
                        String tenantId) {
    }

    /**
     * @param covered   a ticket fits every condition
     * @param ticketKey the fitting ticket, or the closest candidate when none fits
     * @param mismatches conditions the closest candidate fails (approver, target, purpose, validity, status)
     */
    record TicketCoverage(boolean covered, String ticketKey, String approver, String purpose, Instant validFrom,
                          Instant validUntil, List<String> mismatches) {

        public static TicketCoverage none() {
            return new TicketCoverage(false, null, null, null, null, null, List.of("NO_TICKET"));
        }
    }

    record OncallStatus(boolean onCall, String rosterKey, String team, Instant startsAt, Instant endsAt) {
    }

    record AssignmentStatus(boolean assigned, String responsibility) {
    }

    record ApprovalCoverage(boolean covered, String approvalKey, String approver, String purpose, int maxItems,
                            Instant validFrom, Instant validUntil, List<String> mismatches) {

        public static ApprovalCoverage none() {
            return new ApprovalCoverage(false, null, null, null, 0, null, null, List.of("NO_APPROVAL"));
        }
    }

    record AccessHistory(int days, int windowDays, String lastAccessDate) {
    }

    record CustomerOwnership(boolean owner, String customerKey, String accountManager, String projectKey) {
    }

    /**
     * @param exists   a ticket with that key exists for the requester (in the company or the run's overlay)
     * @param coverage how that ticket fits the request; {@link TicketCoverage#none()} when it does not exist
     */
    enum NetworkKind {
        OFFICE, TRAVEL, EXTERNAL, UNKNOWN
    }

    /**
     * @param network the office or travel network that contains the address, or null
     * @param planKey the travel plan that covers the address, or null
     */
    record NetworkContext(NetworkKind kind, String clientIp, String network, String planKey, String city,
                          String country) {
    }

    record ClaimCheck(String ticketKey, boolean exists, TicketCoverage coverage) {

        public boolean confirmed() {
            return exists && coverage.covered();
        }
    }
}
