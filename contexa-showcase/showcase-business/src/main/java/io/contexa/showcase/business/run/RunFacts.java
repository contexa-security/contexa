package io.contexa.showcase.business.run;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

/**
 * Company facts a run adds for its chosen conditions, for example a matching or a mismatching ITSM ticket
 * (deck p.13: "change only the company's facts"). Employees are referenced by employee key; the facts are visible
 * only to the principals of the run.
 */
public record RunFacts(List<Ticket> tickets, List<Approval> approvals, List<Oncall> oncall,
                       List<TravelPlan> travel, List<Document> documents, List<Delegation> delegations) {

    public RunFacts(List<Ticket> tickets, List<Approval> approvals, List<Oncall> oncall, List<TravelPlan> travel,
                    List<Document> documents) {
        this(tickets, approvals, oncall, travel, documents, List.of());
    }

    public RunFacts(List<Ticket> tickets, List<Approval> approvals, List<Oncall> oncall) {
        this(tickets, approvals, oncall, List.of(), List.of());
    }

    public RunFacts(List<Ticket> tickets, List<Approval> approvals, List<Oncall> oncall, List<TravelPlan> travel) {
        this(tickets, approvals, oncall, travel, List.of());
    }

    public RunFacts {
        tickets = tickets == null ? List.of() : List.copyOf(tickets);
        approvals = approvals == null ? List.of() : List.copyOf(approvals);
        oncall = oncall == null ? List.of() : List.copyOf(oncall);
        travel = travel == null ? List.of() : List.copyOf(travel);
        documents = documents == null ? List.of() : List.copyOf(documents);
        delegations = delegations == null ? List.of() : List.copyOf(delegations);
    }

    public static RunFacts none() {
        return new RunFacts(List.of(), List.of(), List.of());
    }

    public record Ticket(String ticketKey, String kind, String requester, String approver, String projectKey,
                         String purpose, String summary, Instant validFrom, Instant validUntil, String status) {
    }

    /** @param approvedAt when the approval was decided; null when the case does not say (survey D5) */
    public record Approval(String approvalKey, String requester, String approver, String projectKey, String purpose,
                           int maxItems, Instant validFrom, Instant validUntil, String status, Instant approvedAt) {

        public Approval(String approvalKey, String requester, String approver, String projectKey, String purpose,
                        int maxItems, Instant validFrom, Instant validUntil, String status) {
            this(approvalKey, requester, approver, projectKey, purpose, maxItems, validFrom, validUntil, status, null);
        }
    }

    /**
     * Work a person delegated to an agent (docs/agent A7-0): the delegation of record the engine reads through its
     * delegation record lookup.
     *
     * @param delegator  the employee key of the person who delegated the work
     * @param agentId    the run's agent the work was delegated to
     * @param recordedBy who wrote the record (an employee key or an agent id), or null when it does not say (A2-10)
     * @param recordedAt when the record was written, or null when it does not say (A2-10)
     */
    public record Delegation(String delegationKey, String delegator, String agentId, String objectiveId,
                             String objectiveFamily, String summary, List<String> operations, List<String> resources,
                             boolean approvalRequired, Instant validFrom, Instant expiresAt, boolean revoked,
                             String recordedBy, Instant recordedAt) {

        public Delegation {
            operations = operations == null ? List.of() : List.copyOf(operations);
            resources = resources == null ? List.of() : List.copyOf(resources);
        }

        /** A record that does not say who wrote it or when. */
        public Delegation(String delegationKey, String delegator, String agentId, String objectiveId,
                          String objectiveFamily, String summary, List<String> operations, List<String> resources,
                          boolean approvalRequired, Instant validFrom, Instant expiresAt, boolean revoked) {
            this(delegationKey, delegator, agentId, objectiveId, objectiveFamily, summary, operations, resources,
                    approvalRequired, validFrom, expiresAt, revoked, null, null);
        }
    }

    /** A registered business trip: the network the employee works from while away (deck A1). */
    public record TravelPlan(String planKey, String employeeKey, String city, String country, String networkCidr,
                             Instant validFrom, Instant validUntil) {
    }

    public record Oncall(String rosterKey, String employeeKey, String team, Instant startsAt, Instant endsAt) {
    }

    /**
     * A document the run's case adds (W2-6). The author summary is the author's own text; the engine receives it as
     * untrusted author text, never as an approval record.
     */
    public record Document(String documentKey, String projectKey, String documentType, String title, String revision,
                           String sensitivity, String body, String authorName, String authorSummary,
                           LocalDate updatedOn) {
    }
}
