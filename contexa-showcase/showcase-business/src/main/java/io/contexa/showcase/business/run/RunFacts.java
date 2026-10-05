package io.contexa.showcase.business.run;

import java.time.Instant;
import java.util.List;

/**
 * Company facts a run adds for its chosen conditions, for example a matching or a mismatching ITSM ticket
 * (deck p.13: "change only the company's facts"). Employees are referenced by employee key; the facts are visible
 * only to the principals of the run.
 */
public record RunFacts(List<Ticket> tickets, List<Approval> approvals, List<Oncall> oncall,
                       List<TravelPlan> travel) {

    public RunFacts(List<Ticket> tickets, List<Approval> approvals, List<Oncall> oncall) {
        this(tickets, approvals, oncall, List.of());
    }

    public RunFacts {
        tickets = tickets == null ? List.of() : List.copyOf(tickets);
        approvals = approvals == null ? List.of() : List.copyOf(approvals);
        oncall = oncall == null ? List.of() : List.copyOf(oncall);
        travel = travel == null ? List.of() : List.copyOf(travel);
    }

    public static RunFacts none() {
        return new RunFacts(List.of(), List.of(), List.of());
    }

    public record Ticket(String ticketKey, String kind, String requester, String approver, String projectKey,
                         String purpose, String summary, Instant validFrom, Instant validUntil, String status) {
    }

    public record Approval(String approvalKey, String requester, String approver, String projectKey, String purpose,
                           int maxItems, Instant validFrom, Instant validUntil, String status) {
    }

    /** A registered business trip: the network the employee works from while away (deck A1). */
    public record TravelPlan(String planKey, String employeeKey, String city, String country, String networkCidr,
                             Instant validFrom, Instant validUntil) {
    }

    public record Oncall(String rosterKey, String employeeKey, String team, Instant startsAt, Instant endsAt) {
    }
}
