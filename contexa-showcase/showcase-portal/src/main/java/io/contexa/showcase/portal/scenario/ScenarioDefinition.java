package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.work.BusinessOperation;

import java.time.Duration;
import java.time.LocalDate;
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
 * @param frozenOn the day the case definition was frozen (W2-5); a later change gives a new version and day. The
 *                 visitor API publishes it with the definition's hash. Null for a case a visitor composed in the lab
 * @param suite    the group the benchmark also counts the case in, such as {@link #RULE_BLIND}; null for none
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
        Network network,
        @JsonInclude(JsonInclude.Include.NON_NULL) LocalDate frozenOn,
        @JsonInclude(JsonInclude.Include.NON_NULL) String suite) {

    /**
     * Cases whose ground truth the business-record rules (C2) cannot tell from the records they read: the request
     * is within an assignment or an approval, and only behaviour, timing or the sum of requests differs. The
     * benchmark counts them as a group so the comparison does not rest on rules written for the other cases.
     */
    public static final String RULE_BLIND = "RULE_BLIND";

    /**
     * W7-5: normal work in combinations the rules were not written for and the other cases do not show: a laptop used
     * for the first time on a registered trip at the company's dawn (S14), usual work on a resource of internal grade
     * while every other case's resource is confidential or above (S15, deep analysis A-16), and exports that add up
     * within an approval (S11T, the counterpart of S11). Their results are published as they come out.
     */
    public static final String NORMAL_COMBINATION = "NORMAL_COMBINATION";

    public ScenarioDefinition(String key, int version, Map<String, String> title, String protagonist, boolean template,
                              TimeSlot timeSlot, Device device, Pace pace, List<Fact> facts, List<Step> steps,
                              Oracle oracle, Network network) {
        this(key, version, title, protagonist, template, timeSlot, device, pace, facts, steps, oracle, network, null,
                null);
    }

    public ScenarioDefinition(String key, int version, Map<String, String> title, String protagonist, boolean template,
                              TimeSlot timeSlot, Device device, Pace pace, List<Fact> facts, List<Step> steps,
                              Oracle oracle, Network network, LocalDate frozenOn) {
        this(key, version, title, protagonist, template, timeSlot, device, pace, facts, steps, oracle, network,
                frozenOn, null);
    }

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
     * @param kind     TICKET, APPROVAL, ONCALL (the protagonist's on-call duty; {@code team} names the team), TRAVEL
     *                 (a registered business trip of the protagonist in {@code city}, {@code country} from
     *                 {@code network}) or DOCUMENT (a document of {@code project} the run adds, case S09)
     * @param network          CIDR block of a TRAVEL fact
     * @param document         the document of a DOCUMENT fact
     * @param recordedAtOffset when an APPROVAL fact's decision was recorded, from the scenario's company time; null
     *                         when the record does not say (case S12 records it after the request)
     */
    public record Fact(String kind, String ticketKind, String approver, String project, String purpose,
                       Integer maxItems, Duration validFromOffset, Duration validUntilOffset, String status,
                       String team, String city, String country, String network, DocumentText document,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Duration recordedAtOffset) {

        public Fact(String kind, String ticketKind, String approver, String project, String purpose, Integer maxItems,
                    Duration validFromOffset, Duration validUntilOffset, String status, String team, String city,
                    String country, String network) {
            this(kind, ticketKind, approver, project, purpose, maxItems, validFromOffset, validUntilOffset, status,
                    team, city, country, network, null, null);
        }
    }

    /**
     * The text of a document a case adds, kept as its source wrote it (W2-6: the OSS Runtime Lab's S09 documents,
     * V28__untrusted_demonstration_document.sql). The engine receives the English summary as the author's untrusted
     * text; the Korean text is for the screens.
     *
     * @param source where the text was copied from, word for word
     */
    public record DocumentText(String source, String type, String sensitivity, String author, String updatedOn,
                               Map<String, String> title, Map<String, String> summary, Map<String, String> body) {
    }

    /**
     * A document named by position (1-based, key order) among a project's documents of a type, or the document the
     * run's N-th fact adds ({@code fact}, 1-based).
     */
    public record DocumentSelector(String project, String type, int position, Integer fact) {

        public DocumentSelector(String project, String type, int position) {
            this(project, type, position, null);
        }
    }

    /**
     * @param expected expected decision of the rule controls (A, B, C1, C2): ALLOW or DENY
     */
    /**
     * @param claimedTicket  a ticket the requester names in the request (deck A8); {@code {fact:N}} names the key the
     *                       run gives to its N-th fact, any other value is sent as written
     * @param grantee        employee who receives the role of a ROLE_GRANT step (deck A5)
     * @param responsibility role given by a ROLE_GRANT step
     * @param visitorSends   the visitor sends this step: a live run waits for the visitor's press before it (the
     *                       attacker trying again in docs/showcase/화면설계서.md scene 2); a recording sends it at once
     * @param body           W7-4 (docs/showcase/프롬프트-최종-구현계획.md 8.7, the request body): the JSON object a POST
     *                       step sends as its body; null sends an empty body, as before
     * @param headers        W7-4 (8.7, an X-Contexa-Anomaly-Signal header the requester has no authority to send):
     *                       headers the requester adds, sent as written to every control; null for none
     * @param requestIdOf    W7-4 (8.7, an X-Request-ID equal to the previous request's): the number (1-based) of an
     *                       earlier step whose request id this step sends as its X-Request-ID; each control sends the
     *                       id it sent that step with, while the request keeps a processing id of its own
     */
    public record Step(BusinessOperation operation, DocumentSelector document, String project, String customer,
                       Integer items, long offsetSeconds, Map<String, String> expected, String claimedTicket,
                       String grantee, String responsibility, Boolean visitorSends,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Map<String, Object> body,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Map<String, String> headers,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Integer requestIdOf) {

        /** A step that names no request part beyond its path; its definition hash is the one it had before W7-4. */
        public Step(BusinessOperation operation, DocumentSelector document, String project, String customer,
                    Integer items, long offsetSeconds, Map<String, String> expected, String claimedTicket,
                    String grantee, String responsibility, Boolean visitorSends) {
            this(operation, document, project, customer, items, offsetSeconds, expected, claimedTicket, grantee,
                    responsibility, visitorSends, null, null, null);
        }

        public boolean sentByVisitor() {
            return Boolean.TRUE.equals(visitorSends);
        }
    }

    /**
     * @param classification NORMAL, THREAT, UNCERTAIN (the ground truth set outside the engine, deck p.32), or
     *                       COMPOSED for a case a visitor changed in the lab (no ground truth)
     * @param allowedEngineActions engine decisions that count as correct for this scenario
     * @param rationale      why the ground truth is what it is, ko and en (review R-40); never sent to the engine
     * @param counterpoint   the expected objection to the ground truth and why the case decides as it does, ko and en
     *                       (review R-16); never sent to the engine
     */
    public record Oracle(String classification, List<String> allowedEngineActions, Map<String, String> rationale,
                         @JsonInclude(JsonInclude.Include.NON_NULL) Map<String, String> counterpoint) {

        public Oracle(String classification, List<String> allowedEngineActions) {
            this(classification, allowedEngineActions, null, null);
        }

        public Oracle(String classification, List<String> allowedEngineActions, Map<String, String> rationale) {
            this(classification, allowedEngineActions, rationale, null);
        }
    }
}
