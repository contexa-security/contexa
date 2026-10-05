package io.contexa.showcase.portal.scenario;

import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.work.BusinessOperation;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * One scenario: a protagonist, the company time and device, the company facts the run adds, and the request
 * sequence every control receives (deck p.24: the same request order is copied to the five controls). The expected
 * outcome of the rule controls is stated per step from their published configuration; control D has only the
 * oracle's range, because its result is measured (deck p.1).
 *
 * @param template whether the run principal is cloned from the protagonist's learned template; false gives a
 *                 principal with no history (scenario S08)
 * @param pace     PACED waits past the engine's ALLOW window between steps so every step is analysed; RAPID sends
 *                 the steps back to back
 */
public record ScenarioDefinition(
        String key,
        int version,
        Map<String, String> title,
        String protagonist,
        boolean template,
        TimeSlot timeSlot,
        Device device,
        Pace pace,
        List<Fact> facts,
        List<Step> steps,
        Oracle oracle,
        Network network) {

    public enum Device {
        USUAL, NEW
    }

    /**
     * Where the run principal connects from (deck A1, A2): the employee's office network (default), an address outside
     * every company network, or the network of the scenario's TRAVEL fact.
     */
    public enum Network {
        OFFICE, EXTERNAL, TRAVEL
    }

    public Network networkOrDefault() {
        return network == null ? Network.OFFICE : network;
    }

    public enum Pace {
        PACED, RAPID
    }

    /**
     * A company fact the run adds (deck p.13: only the company's facts change). Times are offsets from the
     * scenario's company time.
     */
    /**
     * @param kind    TICKET, APPROVAL, ONCALL (the protagonist's on-call duty; {@code team} names the team) or TRAVEL
     *                (a registered business trip of the protagonist in {@code city}, {@code country} from
     *                {@code network})
     * @param network CIDR block of a TRAVEL fact
     */
    public record Fact(String kind, String ticketKind, String approver, String project, String purpose,
                       Integer maxItems, Duration validFromOffset, Duration validUntilOffset, String status,
                       String team, String city, String country, String network) {
    }

    /** A document named by position (1-based, key order) among a project's documents of a type. */
    public record DocumentSelector(String project, String type, int position) {
    }

    /**
     * @param expected expected decision of the rule controls (A, B, C1, C2): ALLOW or DENY
     */
    /**
     * @param claimedTicket  a ticket the requester names in the request (deck A8); {@code {fact:N}} names the key the
     *                       run gives to its N-th fact, any other value is sent as written
     * @param grantee        employee who receives the role of a ROLE_GRANT step (deck A5)
     * @param responsibility role given by a ROLE_GRANT step
     */
    public record Step(BusinessOperation operation, DocumentSelector document, String project, String customer,
                       Integer items, long offsetSeconds, Map<String, String> expected, String claimedTicket,
                       String grantee, String responsibility) {
    }

    /**
     * @param classification NORMAL, THREAT, UNCERTAIN (the ground truth set outside the engine, deck p.32)
     * @param allowedEngineActions engine decisions that count as correct for this scenario
     */
    public record Oracle(String classification, List<String> allowedEngineActions) {
    }
}
