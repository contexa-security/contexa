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
                       List<TravelPlan> travel, List<Document> documents) {

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
