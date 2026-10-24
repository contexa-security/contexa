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
 * @param agent    docs/agent A7-0: the run's agent, which the protagonist delegates work to or which acts on its own;
 *                 null for a case without one
 * @param task     docs/agent A7-2c: the work the protagonist gives the agent, which a real business agent then does
 *                 with the company's tools (its requests are the run's steps); null for a case of scripted steps
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
        @JsonInclude(JsonInclude.Include.NON_NULL) String suite,
        @JsonInclude(JsonInclude.Include.NON_NULL) Agent agent,
        @JsonInclude(JsonInclude.Include.NON_NULL) AgentTask task) {

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

    /**
     * docs/agent A6-R0: this agent task case on one of the paths it is measured on (A6-D2): the work and every step
     * of the case's agent are sent that way; the person's steps stay. The case is unchanged on its own path.
     *
     * @throws IllegalArgumentException when the case is not measured on that path
     */
    public ScenarioDefinition onPath(Sender path) {
        if (task == null || agent == null) {
            throw new IllegalArgumentException("Only an agent task case has paths");
        }
        if (path == null || path == Sender.PERSON || !task.measuredPaths().contains(path)) {
            throw new IllegalArgumentException("The case " + key + " is not measured on " + path);
        }
        if (path == task.sender()) {
            return this;
        }
        return new ScenarioDefinition(key, version, title, protagonist, template, timeSlot, device, pace, facts,
                steps.stream().map(step -> step.onAgentPath(path)).toList(), oracle, network, frozenOn, suite, agent,
                task.on(path));
    }

    public ScenarioDefinition(String key, int version, Map<String, String> title, String protagonist, boolean template,
                              TimeSlot timeSlot, Device device, Pace pace, List<Fact> facts, List<Step> steps,
                              Oracle oracle, Network network) {
        this(key, version, title, protagonist, template, timeSlot, device, pace, facts, steps, oracle, network, null,
                null, null);
    }

    /** A case without an agent (the form before docs/agent A7-0); its definition hash is unchanged. */
    public ScenarioDefinition(String key, int version, Map<String, String> title, String protagonist, boolean template,
                              TimeSlot timeSlot, Device device, Pace pace, List<Fact> facts, List<Step> steps,
                              Oracle oracle, Network network, LocalDate frozenOn, String suite) {
        this(key, version, title, protagonist, template, timeSlot, device, pace, facts, steps, oracle, network,
                frozenOn, suite, null);
    }

    /**
     * docs/agent A7-0: the run's agent. The run registers it in control D with its own OAuth2 client and, when a step
     * sends as {@link Sender#AGENT_SESSION}, an account of its own.
     *
     * @param name      a short name; the run's agent is named after the run and this name
     * @param title     the name the screens show, ko and en
     * @param roleKey   the company role whose work the agent does: the scope its token holds and its account's role
     * @param network   CIDR block of the network the agent runs in
     * @param userAgent the user agent the agent's HTTP client sends
     */
    public record Agent(String name, Map<String, String> title, String roleKey, String network, String userAgent) {
    }

    /** A case without an agent task (every case before docs/agent A7-2c); its definition hash is unchanged. */
    public ScenarioDefinition(String key, int version, Map<String, String> title, String protagonist, boolean template,
                              TimeSlot timeSlot, Device device, Pace pace, List<Fact> facts, List<Step> steps,
                              Oracle oracle, Network network, LocalDate frozenOn, String suite, Agent agent) {
        this(key, version, title, protagonist, template, timeSlot, device, pace, facts, steps, oracle, network,
                frozenOn, suite, agent, null);
    }

    /**
     * docs/agent A7-2c: the work a person gives the case's business agent.
     *
     * @param instruction  what the person asks, in the person's words, per language
     * @param agentPrompt  the agent's own instruction; null for the business agent's (a case that tampers with the
     *                     agent's instruction gives its own)
     * @param sender       how the agent reaches control D: for the person (an exchanged token), on its own, or with
     *                     its own account
     * @param model        the agent's model; null for the portal's setting
     * @param maxToolCalls the most tool calls the work may make; null for the portal's setting
     * @param maxSeconds   the longest the work may take; null for the portal's setting
     * @param tools        the business operations the agent's tools offer (their names)
     * @param proof        what proves the work done, and what must not leave the company in an attack
     * @param offsetSeconds when the work starts, in seconds after the case's company time (after its scripted steps,
     *                     which come first); null for at once
     * @param runtime      where the work's requests to control D come from when not from the case's agent (a stolen
     *                     token used by another agent runtime); null for the case's agent
     * @param newSession   docs/agent A4 (real server): the work starts a session of its own, as a step that starts one
     *                     (the person signs in again and the agent gets a new token), so the agent's work on earlier
     *                     days in the case's scripted steps is its history and not this session; null or false keeps
     *                     the last scripted step's session
     */
    public record AgentTask(Map<String, String> instruction,
                            @JsonInclude(JsonInclude.Include.NON_NULL) String agentPrompt, Sender sender,
                            @JsonInclude(JsonInclude.Include.NON_NULL) String model,
                            @JsonInclude(JsonInclude.Include.NON_NULL) Integer maxToolCalls,
                            @JsonInclude(JsonInclude.Include.NON_NULL) Integer maxSeconds,
                            List<BusinessOperation> tools, Proof proof,
                            @JsonInclude(JsonInclude.Include.NON_NULL) Long offsetSeconds,
                            @JsonInclude(JsonInclude.Include.NON_NULL) AgentRuntime runtime,
                            @JsonInclude(JsonInclude.Include.NON_NULL) Boolean newSession,
                            @JsonInclude(JsonInclude.Include.NON_NULL) List<Sender> paths) {

        public AgentTask {
            tools = tools == null ? List.of() : List.copyOf(tools);
            paths = paths == null ? null : List.copyOf(paths);
        }

        /** The work before docs/agent A6-R0 (one path, its sender); its definition hash is unchanged. */
        public AgentTask(Map<String, String> instruction, String agentPrompt, Sender sender, String model,
                         Integer maxToolCalls, Integer maxSeconds, List<BusinessOperation> tools, Proof proof,
                         Long offsetSeconds, AgentRuntime runtime, Boolean newSession) {
            this(instruction, agentPrompt, sender, model, maxToolCalls, maxSeconds, tools, proof, offsetSeconds,
                    runtime, newSession, null);
        }

        /** docs/agent A6-D2: the paths the work is measured on; its sender alone when the case names none. */
        public List<Sender> measuredPaths() {
            return paths != null && !paths.isEmpty() ? paths : List.of(sender);
        }

        /** The same work sent on another path. */
        public AgentTask on(Sender path) {
            return new AgentTask(instruction, agentPrompt, path, model, maxToolCalls, maxSeconds, tools, proof,
                    offsetSeconds, runtime, newSession, paths);
        }

        public AgentTask(Map<String, String> instruction, String agentPrompt, Sender sender, String model,
                         Integer maxToolCalls, Integer maxSeconds, List<BusinessOperation> tools, Proof proof) {
            this(instruction, agentPrompt, sender, model, maxToolCalls, maxSeconds, tools, proof, null, null, null,
                    null);
        }

        /** Whether the work starts a session of its own. */
        public boolean startsNewSession() {
            return Boolean.TRUE.equals(newSession);
        }

        /**
         * Another agent runtime sending with the case's agent's credentials.
         *
         * @param network   the network its requests come from
         * @param userAgent its client
         */
        public record AgentRuntime(String network, String userAgent) {
        }

        /**
         * @param deliverable  what the person expects back when the work is legitimate; null for an attack case
         * @param mustNotLeave the projects whose company data (documents, exported items, customer records) must not
         *                     leave the company in an attack case; empty for a legitimate case
         * @param workNeeds    how many of those documents and records the given work itself needs (a runaway case
         *                     reads the project it was given, beyond what the work needs); null for none
         */
        public record Proof(@JsonInclude(JsonInclude.Include.NON_NULL) String deliverable,
                            List<String> mustNotLeave,
                            @JsonInclude(JsonInclude.Include.NON_NULL) Integer workNeeds) {

            public Proof {
                mustNotLeave = mustNotLeave == null ? List.of() : List.copyOf(mustNotLeave);
            }

            public Proof(String deliverable, List<String> mustNotLeave) {
                this(deliverable, mustNotLeave, null);
            }
        }
    }

    /**
     * docs/agent A7-0: who sends a step to control D. The rule controls know no agents and always receive the step
     * from the person's session, as an agent that signs in with the person's credentials reaches them today.
     */
    /**
     * docs/agent A3-8: what the run's security administrator does to what the case's agent learned before a step,
     * through the engine's administrator API: QUARANTINE, RELEASE or REMOVE, for the whole agent or, with
     * {@code delegation}, for the run's delegation only. Internal agent cases use it to check the control.
     */
    public record LearningAction(String action, @JsonInclude(JsonInclude.Include.NON_NULL) Boolean delegation,
                                 String reason) {

        public boolean forDelegation() {
            return Boolean.TRUE.equals(delegation);
        }
    }

    public enum Sender {
        /** The person (the protagonist), as every case before agents. */
        PERSON,
        /** The agent acting for the person, with a token exchanged from the person's (RFC 8693 act). */
        DELEGATED_AGENT,
        /** The agent acting on its own, with its own client credentials token. */
        AUTONOMOUS_AGENT,
        /** The agent signed in with its own account in the people's session flow. */
        AGENT_SESSION
    }

    public ScenarioDefinition(String key, int version, Map<String, String> title, String protagonist, boolean template,
                              TimeSlot timeSlot, Device device, Pace pace, List<Fact> facts, List<Step> steps,
                              Oracle oracle, Network network, LocalDate frozenOn) {
        this(key, version, title, protagonist, template, timeSlot, device, pace, facts, steps, oracle, network,
                frozenOn, null, null);
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
     *                         when the record does not say (case S12 records it after the request). A DELEGATION
     *                         fact's record is written by the protagonist at this time, or when the delegation begins
     *                         without it (docs/agent A2-10)
     */
    public record Fact(String kind, String ticketKind, String approver, String project, String purpose,
                       Integer maxItems, Duration validFromOffset, Duration validUntilOffset, String status,
                       String team, String city, String country, String network, DocumentText document,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Duration recordedAtOffset,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Delegated delegated) {

        /** A fact of the form before docs/agent A7-0; its definition hash is unchanged. */
        public Fact(String kind, String ticketKind, String approver, String project, String purpose, Integer maxItems,
                    Duration validFromOffset, Duration validUntilOffset, String status, String team, String city,
                    String country, String network, DocumentText document, Duration recordedAtOffset) {
            this(kind, ticketKind, approver, project, purpose, maxItems, validFromOffset, validUntilOffset, status,
                    team, city, country, network, document, recordedAtOffset, null);
        }

        public Fact(String kind, String ticketKind, String approver, String project, String purpose, Integer maxItems,
                    Duration validFromOffset, Duration validUntilOffset, String status, String team, String city,
                    String country, String network) {
            this(kind, ticketKind, approver, project, purpose, maxItems, validFromOffset, validUntilOffset, status,
                    team, city, country, network, null, null, null);
        }
    }

    /**
     * docs/agent A7-0: what a DELEGATION fact delegates to the run's agent. The fact's {@code purpose} is the objective
     * family, {@code project} the project the work is on, {@code status} ACTIVE or REVOKED, and its offsets the
     * delegation's validity.
     *
     * @param summary          what the person asked the agent to do, ko and en; the engine reads the English text
     * @param operations       the operations delegated, as the business operations name them
     * @param resources        the resources delegated; a project key names that project's records
     * @param approvalRequired whether a person must approve the agent's work
     */
    public record Delegated(Map<String, String> summary, List<String> operations, List<String> resources,
                            boolean approvalRequired) {
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
     * @param newSession     N-INJ-5 (8.7, the label of a request that becomes a past record): every control signs the
     *                       run principal in again two minutes before this step and sends it and the later steps in
     *                       that new session. The engine leaves a request's own session out of its past records
     *                       (W3-18), so the allowed requests of the earlier session become past records of the later
     *                       steps. Null or false keeps the session; the first step cannot start one
     */
    public record Step(BusinessOperation operation, DocumentSelector document, String project, String customer,
                       Integer items, long offsetSeconds, Map<String, String> expected, String claimedTicket,
                       String grantee, String responsibility, Boolean visitorSends,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Map<String, Object> body,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Map<String, String> headers,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Integer requestIdOf,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Boolean newSession,
                       @JsonInclude(JsonInclude.Include.NON_NULL) Sender sender,
                       @JsonInclude(JsonInclude.Include.NON_NULL) LearningAction learningAction) {

        /** A step with no learning action before it (the A7-0 form); its definition hash is unchanged. */
        public Step(BusinessOperation operation, DocumentSelector document, String project, String customer,
                    Integer items, long offsetSeconds, Map<String, String> expected, String claimedTicket,
                    String grantee, String responsibility, Boolean visitorSends, Map<String, Object> body,
                    Map<String, String> headers, Integer requestIdOf, Boolean newSession, Sender sender) {
            this(operation, document, project, customer, items, offsetSeconds, expected, claimedTicket, grantee,
                    responsibility, visitorSends, body, headers, requestIdOf, newSession, sender, null);
        }

        /** A step the person sends (the form before docs/agent A7-0); its definition hash is unchanged. */
        public Step(BusinessOperation operation, DocumentSelector document, String project, String customer,
                    Integer items, long offsetSeconds, Map<String, String> expected, String claimedTicket,
                    String grantee, String responsibility, Boolean visitorSends, Map<String, Object> body,
                    Map<String, String> headers, Integer requestIdOf, Boolean newSession) {
            this(operation, document, project, customer, items, offsetSeconds, expected, claimedTicket, grantee,
                    responsibility, visitorSends, body, headers, requestIdOf, newSession, null);
        }

        /** A step that names no request part beyond its path; its definition hash is the one it had before W7-4. */
        public Step(BusinessOperation operation, DocumentSelector document, String project, String customer,
                    Integer items, long offsetSeconds, Map<String, String> expected, String claimedTicket,
                    String grantee, String responsibility, Boolean visitorSends) {
            this(operation, document, project, customer, items, offsetSeconds, expected, claimedTicket, grantee,
                    responsibility, visitorSends, null, null, null, null, null);
        }

        /** A step in the session of the step before it (the W7-4 form); its hash is the one it had before N-INJ-5. */
        public Step(BusinessOperation operation, DocumentSelector document, String project, String customer,
                    Integer items, long offsetSeconds, Map<String, String> expected, String claimedTicket,
                    String grantee, String responsibility, Boolean visitorSends, Map<String, Object> body,
                    Map<String, String> headers, Integer requestIdOf) {
            this(operation, document, project, customer, items, offsetSeconds, expected, claimedTicket, grantee,
                    responsibility, visitorSends, body, headers, requestIdOf, null, null);
        }

        public boolean sentByVisitor() {
            return Boolean.TRUE.equals(visitorSends);
        }

        /** N-INJ-5: whether every control signs in again before this step and sends it in that new session. */
        public boolean startsNewSession() {
            return Boolean.TRUE.equals(newSession);
        }

        /** docs/agent A7-0: who sends the step to control D; the person when the step names no one. */
        public Sender senderOrPerson() {
            return sender == null ? Sender.PERSON : sender;
        }

        /** docs/agent A6-R0: the same step sent by the case's agent on another path; a person's step stays. */
        public Step onAgentPath(Sender path) {
            if (sender == null || sender == Sender.PERSON) {
                return this;
            }
            return new Step(operation, document, project, customer, items, offsetSeconds, expected, claimedTicket,
                    grantee, responsibility, visitorSends, body, headers, requestIdOf, newSession, path,
                    learningAction);
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
    /**
     * @param actor who acts in the case when it is not who the classification says: {@link #OWNER_ACTS} for a threat the
     *              account's owner carries out (an insider, IN-6), who holds the mailbox an additional check sends its
     *              code to; null otherwise (a threat is someone else holding the account, normal work is the owner's)
     */
    public record Oracle(String classification, List<String> allowedEngineActions, Map<String, String> rationale,
                         @JsonInclude(JsonInclude.Include.NON_NULL) Map<String, String> counterpoint,
                         @JsonInclude(JsonInclude.Include.NON_NULL) String actor) {

        public static final String OWNER_ACTS = "OWNER";

        public Oracle(String classification, List<String> allowedEngineActions) {
            this(classification, allowedEngineActions, null, null, null);
        }

        public Oracle(String classification, List<String> allowedEngineActions, Map<String, String> rationale) {
            this(classification, allowedEngineActions, rationale, null, null);
        }

        public Oracle(String classification, List<String> allowedEngineActions, Map<String, String> rationale,
                      Map<String, String> counterpoint) {
            this(classification, allowedEngineActions, rationale, counterpoint, null);
        }

        /** Whether the account's owner carries the case out, as an insider does. */
        public boolean ownerActs() {
            return OWNER_ACTS.equals(actor);
        }
    }
}
