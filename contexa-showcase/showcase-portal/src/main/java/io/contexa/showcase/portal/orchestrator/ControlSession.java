package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.Response;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.orchestrator.ExportStreamReader.Progress;
import io.contexa.showcase.portal.orchestrator.ExportStreamReader.Reading;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * One run principal signed in to one control, with its own cookie store (deck p.24: each control keeps its own
 * session). Sends a step and turns the HTTP response into the step's business outcome: was the data delivered.
 */
public class ControlSession {

    private static final int EXCERPT = 2_000;

    /**
     * @param outcome DELIVERED, REFUSED, NOT_FOUND, ERROR or CUT (only on the engine's own marker)
     * @param stream  how far a streamed export got over time; null for other operations
     */
    public record StepOutcome(String requestId, String method, String path, Instant companyTime, Integer httpStatus,
                              String outcome, int deliveredItems, String ruleId, String reason, String excerpt,
                              long elapsedMs, Instant sentAt, Progress stream) {
    }

    /**
     * W7-4: the parts of a step's request beyond its method and path that a case definition names
     * (docs/showcase/프롬프트-최종-구현계획.md 8.7), sent as written to every control.
     *
     * @param body    the JSON text of a POST request's body; null sends an empty body, as before
     * @param headers the headers the requester adds, in the order they are sent; never null
     */
    public record RequestParts(String body, Map<String, String> headers) {

        public static final RequestParts NONE = new RequestParts(null, Map.of());

        public RequestParts {
            headers = headers == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(headers));
        }
    }

    private final Control control;
    private final WorkloadClient client;
    private final ObjectMapper json;
    /**
     * docs/agent A7-2b: the body of the last answer this session received, as the control sent it, which a business
     * agent's tool hands back to the agent; a stream's answer is the head it read.
     */
    private volatile String lastBody;

    public ControlSession(Control control, WorkloadClient client, ObjectMapper json) {
        this.control = control;
        this.client = client;
        this.json = json;
    }

    public Control control() {
        return control;
    }

    public WorkloadClient client() {
        return client;
    }

    /** This session (same cookies) sending from another address; itself when the address is the same or absent. */
    public ControlSession fromAddress(String clientIp) {
        WorkloadClient moved = client.withClientIp(clientIp);
        return moved == client ? this : new ControlSession(control, moved, json);
    }

    /**
     * docs/agent A7-2d: this session's access token sent by another agent runtime, from its address and with its user
     * agent (a stolen token used elsewhere).
     */
    public ControlSession carriedTo(String clientIp, String userAgent) {
        WorkloadClient.RunIdentity run = client.run();
        return new ControlSession(control, client.carriedTo(new WorkloadClient.RunIdentity(run.runId(),
                run.organization(), run.tenant(), clientIp, userAgent)), json);
    }

    /** JSON sign-in of a plain control. */
    public void signInPlain(String username, String password, Instant companyTime) throws IOException {
        Response login = client.postJson("/api/login", UUID.randomUUID().toString(), companyTime,
                json.writeValueAsString(Map.of("username", username, "password", password)));
        if (login.status() != 200) {
            throw new IOException(control + " sign-in failed: " + login.status() + " " + login.text());
        }
    }

    /** Engine sign-in of control D: JSON login, then the email one-time code read from the demo inbox. */
    public void signInEngine(String username, String password, String email, Instant companyTime, WorkloadAdmin admin)
            throws IOException {
        Response login = client.postJson("/api/mfa/login", UUID.randomUUID().toString(), companyTime,
                json.writeValueAsString(Map.of("username", username, "password", password)));
        if (login.status() != 200) {
            throw new IOException("D sign-in failed: " + login.status() + " " + login.text());
        }
        String status = json.readTree(login.body()).path("status").asText();
        if ("MFA_REQUIRED".equals(status)) {
            completeOneTimeCode(username, email, companyTime, admin);
        }
    }

    public void completeOneTimeCode(String username, String email, Instant companyTime, WorkloadAdmin admin)
            throws IOException {
        Response generate = client.postForm("/mfa/ott/generate-code", UUID.randomUUID().toString(), companyTime,
                Map.of("username", username));
        if (generate.status() != 200 && generate.status() != 302) {
            throw new IOException("D one-time code request failed: " + generate.status() + " " + generate.text());
        }
        String code = admin.inboxCode(email).orElseThrow(() -> new IOException("No one-time code in the demo inbox"));
        Response verify = client.postForm("/login/mfa-ott", UUID.randomUUID().toString(), companyTime,
                Map.of("token", code));
        if (verify.status() != 200) {
            throw new IOException("D one-time code verification failed: " + verify.status() + " " + verify.text());
        }
    }

    /**
     * The additional check of a step (deck p.12). Times are instants so they line up with the step's send time.
     *
     * @param answered  the run principal completed the one-time code; false when it has no mailbox or a step failed
     * @param reason    NO_MAILBOX, or what failed
     * @param reissue   the original request sent again after the check; null when not answered
     */
    public record ChallengeTrace(boolean answered, String reason, Instant challengedAt, Instant codeRequestedAt,
                                 Instant verifiedAt, StepOutcome reissue) {
    }

    /**
     * True when control D answered the step with the engine's additional check: 401 MFA_CHALLENGE_REQUIRED when an
     * earlier CHALLENGE still applies, or 401 ZERO_TRUST_CHALLENGE when the engine decided CHALLENGE for this very
     * request before answering it (a synchronous @Protectable, such as an export).
     */
    public static boolean challenged(StepOutcome outcome) {
        return outcome.httpStatus() != null && outcome.httpStatus() == 401
                && ("MFA_CHALLENGE_REQUIRED".equals(outcome.ruleId())
                || "ZERO_TRUST_CHALLENGE".equals(outcome.ruleId()));
    }

    /**
     * True when control D refused the step because the engine blocked the account: 403 ACCOUNT_BLOCKED when an earlier
     * BLOCK still applies, or 403 ZERO_TRUST_BLOCK when the engine decided BLOCK for this very request before
     * answering it (a synchronous @Protectable).
     */
    public static boolean blocked(StepOutcome outcome) {
        return outcome.httpStatus() != null && outcome.httpStatus() == 403
                && ("ACCOUNT_BLOCKED".equals(outcome.ruleId()) || "ZERO_TRUST_BLOCK".equals(outcome.ruleId()));
    }

    /**
     * The release of a block (ADR-33). Times are instants so they line up with the step's send time.
     *
     * @param released true when the administrator approved and the original request went out again
     * @param reason   NO_MAILBOX, NOT_ASKED, or what failed
     * @param block    the engine's record of the block as the administrator saw it, null before the request
     * @param reissue  the original request sent again after the approval; null when not approved
     */
    public record ReleaseTrace(boolean released, String reason, Instant blockedAt, Instant codeRequestedAt,
                               Instant verifiedAt, Instant requestedAt, Instant approvedAt, Approver.BlockRecord block,
                               StepOutcome reissue) {

        /** Recordings never ask for a release; the block stays in the record as the engine left it. */
        public static ReleaseTrace notAsked(Instant blockedAt) {
            return new ReleaseTrace(false, "NOT_ASKED", blockedAt, null, null, null, null, null, null);
        }
    }

    /**
     * The run principal's actions on a block of control D, in this session and through the engine's own endpoints:
     * start the check of the blocked account, pass it with the e-mailed code, ask for the release and send the
     * original request again (ADR-33).
     */
    public ReleaseActions releaseActions(String username, String email, BusinessOperation operation, String path,
                                         Instant companyTime, WorkloadAdmin admin) {
        return releaseActions(username, email, operation, path, RequestParts.NONE, companyTime, admin);
    }

    /** W7-4: the same, the original request sent again with the request parts it was first sent with. */
    public ReleaseActions releaseActions(String username, String email, BusinessOperation operation, String path,
                                         RequestParts parts, Instant companyTime, WorkloadAdmin admin) {
        return new ReleaseActions() {
            @Override
            public int startCheck() throws IOException {
                return client.postJson("/contexa/admin/api/aiam/zero-trust/initiate-block-mfa",
                        UUID.randomUUID().toString(), companyTime, "{}").status();
            }

            @Override
            public int requestCode() throws IOException {
                // The engine starts the check of a blocked account on its next ordinary request (401).
                client.get("/api/projects", UUID.randomUUID().toString(), companyTime);
                return client.postForm("/mfa/ott/generate-code", UUID.randomUUID().toString(), companyTime,
                        Map.of("username", username)).status();
            }

            @Override
            public Optional<String> readCode() throws IOException {
                return admin.inboxCode(email);
            }

            @Override
            public int submitCode(String code) throws IOException {
                return client.postForm("/login/mfa-ott", UUID.randomUUID().toString(), companyTime,
                        Map.of("token", code)).status();
            }

            @Override
            public int requestRelease(String reason) throws IOException {
                return client.postJson("/contexa/admin/api/aiam/zero-trust/unblock-request",
                        UUID.randomUUID().toString(), companyTime,
                        json.writeValueAsString(Map.of("reason", reason))).status();
            }

            @Override
            public StepOutcome reissue() throws IOException {
                return send(operation, path, companyTime, parts, SendListener.NONE);
            }
        };
    }

    /**
     * The administrator's view and approval of a release request, through the engine's administrator API in this
     * session, which must belong to a principal with the engine's administrator role (ADR-33).
     */
    public Approver approverActions(Instant companyTime) {
        return new Approver() {
            @Override
            public Optional<Approver.BlockRecord> request(String username) throws IOException {
                Response response = client.get("/contexa/admin/api/blacklist", UUID.randomUUID().toString(),
                        companyTime);
                if (response.status() != 200) {
                    throw new IOException("Block list answered " + response.status());
                }
                Approver.BlockRecord found = null;
                for (JsonNode block : json.readTree(response.body())) {
                    boolean mine = username.equals(block.path("userId").asText())
                            || username.equals(block.path("username").asText());
                    if (mine && (found == null || block.path("id").asLong() > found.id())) {
                        found = new Approver.BlockRecord(block.path("id").asLong(), textOrNull(block, "username"),
                                textOrNull(block, "status"),
                                textOrNull(block, "reasoning"), textOrNull(block, "blockedAt"),
                                textOrNull(block, "unblockReason"),
                                block.hasNonNull("mfaVerified") ? block.path("mfaVerified").asBoolean() : null,
                                textOrNull(block, "unblockRequestedAt"));
                    }
                }
                return Optional.ofNullable(found);
            }

            @Override
            public int approve(long blockId, String reason) throws IOException {
                // ALLOW is the decision that lifts the block; the console offers the same choice.
                return client.postJson("/contexa/admin/api/blacklist/" + blockId + "/resolve",
                        UUID.randomUUID().toString(), companyTime,
                        json.writeValueAsString(Map.of("resolvedAction", "ALLOW", "reason", reason))).status();
            }

            @Override
            public Optional<JsonNode> replaySealed(String requestId, Map<String, Object> request) throws IOException {
                Response response = client.postJson("/contexa/admin/api/sealed-decisions/"
                                + URLEncoder.encode(requestId, StandardCharsets.UTF_8) + "/replay",
                        UUID.randomUUID().toString(), companyTime, json.writeValueAsString(request));
                if (response.status() == 404) {
                    return Optional.empty();
                }
                return Optional.of(answer(response, 200, "The sealed decision replay API"));
            }

            @Override
            public JsonNode putCompanyRecords(JsonNode records) throws IOException {
                return answer(client.postJson("/contexa/admin/api/company-records", UUID.randomUUID().toString(),
                        companyTime, json.writeValueAsString(records)), 200, "The company records API");
            }

            @Override
            public JsonNode registerAgent(Map<String, Object> registration) throws IOException {
                return answer(client.postJson("/contexa/admin/api/agents/register", UUID.randomUUID().toString(),
                        companyTime, json.writeValueAsString(registration)), 201, "The agent registration API");
            }

            @Override
            public JsonNode removeAgent(String agentId) throws IOException {
                return answer(client.postJson("/contexa/admin/api/agents/remove", UUID.randomUUID().toString(),
                        companyTime, json.writeValueAsString(Map.of("agentId", agentId))), 200,
                        "The agent removal API");
            }

            private JsonNode answer(Response response, int expected, String what) throws IOException {
                if (response.status() != expected) {
                    throw new IOException(what + " answered " + response.status() + ": " + new String(
                            response.body() == null ? new byte[0] : response.body(), StandardCharsets.UTF_8));
                }
                return json.readTree(response.body());
            }

            @Override
            public String recordDelegation(Map<String, Object> delegation) throws IOException {
                Response response = client.postJson("/contexa/admin/api/agent-delegations",
                        UUID.randomUUID().toString(), companyTime, json.writeValueAsString(delegation));
                if (response.status() != 201) {
                    throw new IOException("The delegation admin API answered " + response.status() + ": "
                            + new String(response.body() == null ? new byte[0] : response.body(),
                            StandardCharsets.UTF_8));
                }
                return json.readTree(response.body()).path("delegationId").asText();
            }

            @Override
            public Approver.LearningResult agentLearning(String agentId, String delegationId, String action,
                                                         String reason) throws IOException {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("agentId", agentId);
                body.put("delegationId", delegationId);
                body.put("action", action);
                body.put("reason", reason);
                Response response = client.postJson("/contexa/admin/api/agents/learning",
                        UUID.randomUUID().toString(), companyTime, json.writeValueAsString(body));
                JsonNode answer = response.body() == null || response.body().length == 0 ? null
                        : json.readTree(response.body());
                return new Approver.LearningResult(response.status(), answer);
            }
        };
    }

    /** An attacker holds the password and the session but not the mailbox (R1 contract, attacker capability). */
    public static ChallengeTrace abandoned(Instant challengedAt) {
        return new ChallengeTrace(false, "NO_MAILBOX", challengedAt, null, null, null);
    }

    /**
     * The run principal's actions on an additional check of control D, in this session: ask for the one-time code,
     * read it from the demo inbox, submit it, and send the original request again (P3-BE-01).
     */
    public ChallengeActions challengeActions(String username, String email, BusinessOperation operation, String path,
                                             Instant companyTime, WorkloadAdmin admin) {
        return challengeActions(username, email, operation, path, RequestParts.NONE, companyTime, admin);
    }

    /** W7-4: the same, the original request sent again with the request parts it was first sent with. */
    public ChallengeActions challengeActions(String username, String email, BusinessOperation operation, String path,
                                             RequestParts parts, Instant companyTime, WorkloadAdmin admin) {
        return new ChallengeActions() {
            @Override
            public int requestCode() throws IOException {
                return client.postForm("/mfa/ott/generate-code", UUID.randomUUID().toString(), companyTime,
                        Map.of("username", username)).status();
            }

            @Override
            public Optional<String> readCode() throws IOException {
                return admin.inboxCode(email);
            }

            @Override
            public int submitCode(String code) throws IOException {
                return client.postForm("/login/mfa-ott", UUID.randomUUID().toString(), companyTime,
                        Map.of("token", code)).status();
            }

            @Override
            public StepOutcome reissue() throws IOException {
                return send(operation, path, companyTime, parts, SendListener.NONE);
            }
        };
    }

    /** Hears a request of this control as it goes: when it is sent and, for a streamed export, how far it got. */
    public interface SendListener {

        SendListener NONE = new SendListener() {
        };

        default void sent(String requestId, Instant sentAt) {
        }

        default void streamProgress(Integer total, long atMs, int delivered) {
        }
    }

    public StepOutcome send(BusinessOperation operation, String path, Instant companyTime) throws IOException {
        return send(operation, path, companyTime, SendListener.NONE);
    }

    /** The HTTP method the business API takes an operation with. */
    public static String method(BusinessOperation operation) {
        return switch (operation) {
            case EXPORT, EXPORT_ASYNC, ROLE_GRANT -> "POST";
            default -> "GET";
        };
    }

    public StepOutcome send(BusinessOperation operation, String path, Instant companyTime, SendListener listener)
            throws IOException {
        return send(operation, path, companyTime, RequestParts.NONE, listener);
    }

    /**
     * W7-4: sends a step with the request parts its definition names. The request gets a fresh id of its own, which
     * the signed internal context carries and the engine records its decision under; an X-Request-ID among the parts
     * goes beside it as the requester wrote it. A GET request carries no body.
     */
    public StepOutcome send(BusinessOperation operation, String path, Instant companyTime, RequestParts parts,
                            SendListener listener) throws IOException {
        String method = method(operation);
        if (parts.body() != null && !"POST".equals(method)) {
            throw new IllegalArgumentException(operation + " is sent as a GET request and carries no body");
        }
        String requestId = UUID.randomUUID().toString();
        listener.sent(requestId, Instant.now());
        if (operation == BusinessOperation.EXPORT_STREAM) {
            return stream(requestId, path, companyTime, parts.headers(), listener);
        }
        Response response = "POST".equals(method)
                ? client.postJson(path, requestId, companyTime, parts.body(), parts.headers())
                : client.get(path, requestId, companyTime, parts.headers());
        return outcome(requestId, method, path, companyTime, response, operation);
    }

    /** docs/agent A7-2b: the body of the last answer this session received; null before any. */
    public String lastBody() {
        return lastBody;
    }

    private StepOutcome outcome(String requestId, String method, String path, Instant companyTime, Response response,
                                BusinessOperation operation) {
        int status = response.status();
        String text = response.text();
        lastBody = text;
        String outcome;
        int delivered = 0;
        String rule = null;
        String reason = null;
        if (status == 200) {
            outcome = "DELIVERED";
            delivered = operation == BusinessOperation.EXPORT || operation == BusinessOperation.EXPORT_ASYNC
                    ? jsonInt(text, "deliveredItems") : 1;
            if (operation == BusinessOperation.PROJECT_LIST) {
                delivered = 1;
            }
        } else if (status == 404) {
            outcome = "NOT_FOUND";
        } else if (status == 401 || status == 403 || status == 423 || status == 429) {
            // docs/agent DD-27: 429 is control D's call limit for agents (A5-7), a refusal with its code.
            outcome = "REFUSED";
            JsonNode body = jsonOrNull(text);
            if (body != null) {
                rule = ruleOf(body);
                reason = textOrNull(body, "reason");
                if (reason == null) {
                    reason = textOrNull(body, "message");
                }
            } else if (control == Control.A && status == 403) {
                rule = "WAF";
                reason = "Request refused by the web application firewall";
            }
        } else {
            outcome = "ERROR";
        }
        return new StepOutcome(requestId, method, path, companyTime, status, outcome, delivered, rule, reason,
                excerpt(text), response.elapsed().toMillis(), response.sentAt(), null);
    }

    /**
     * The refusal's code: "rule" of the plain controls' rules, "error" of the engine's filters (MFA_CHALLENGE_REQUIRED,
     * ACCOUNT_BLOCKED) or "code" of the engine's synchronous decision (ZERO_TRUST_CHALLENGE, ZERO_TRUST_BLOCK, ...).
     */
    static String ruleOf(JsonNode body) {
        for (String field : new String[] {"rule", "error", "code"}) {
            String value = textOrNull(body, field);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    /**
     * Reads a streamed export to the end or to the engine's cut. The outcome is CUT only when the engine wrote its
     * marker; a stream that breaks or ends short without it is an ERROR (deck p.11, P3-BE-02).
     */
    private StepOutcome stream(String requestId, String path, Instant companyTime, Map<String, String> headers,
                               SendListener listener) throws IOException {
        Instant sentAt = Instant.now();
        long started = System.nanoTime();
        HttpResponse<InputStream> response = client.openStream(path, requestId, companyTime, headers);
        int status = response.statusCode();
        if (status != 200) {
            String text;
            try (InputStream in = response.body()) {
                text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            Response buffered = new Response(status, response.headers().map(), text.getBytes(StandardCharsets.UTF_8),
                    sentAt, Duration.ofNanos(System.nanoTime() - started));
            return outcome(requestId, "GET", path, companyTime, buffered, BusinessOperation.EXPORT_STREAM);
        }
        Integer total = response.headers().firstValue("X-Showcase-Export-Total").map(Integer::valueOf).orElse(null);
        Reading reading = ExportStreamReader.read(response.body(), total,
                () -> (System.nanoTime() - started) / 1_000_000L,
                (atMs, delivered) -> listener.streamProgress(total, atMs, delivered));
        Progress progress = reading.progress();
        lastBody = reading.head();
        String outcome = progress.cut() != null ? "CUT" : progress.interrupted() ? "ERROR" : "DELIVERED";
        String rule = progress.cut() != null ? "ENGINE_CUT" : progress.interrupted() ? "STREAM_INTERRUPTED" : null;
        return new StepOutcome(requestId, "GET", path, companyTime, status, outcome, progress.delivered(), rule,
                progress.cut(), reading.head(), progress.endMs(), sentAt, progress);
    }

    private int jsonInt(String text, String field) {
        JsonNode body = jsonOrNull(text);
        return body == null ? 0 : body.path(field).asInt(0);
    }

    private JsonNode jsonOrNull(String text) {
        try {
            JsonNode node = json.readTree(text);
            return node != null && node.isObject() ? node : null;
        } catch (IOException e) {
            return null;
        }
    }

    /** docs/agent A7-3: control D's answer to an agent's request its delegating person must confirm first (A5-2). */
    public static final String AGENT_CONFIRMATION_REQUIRED = "AGENT_CONFIRMATION_REQUIRED";
    /** docs/agent A7-3: the header an agent sends a confirmed request again with (the engine's own, A5-2). */
    public static final String AGENT_CONFIRMATION_HEADER = "Contexa-Agent-Confirmation";

    /** docs/agent A7-3: true when control D answered an agent's request with a confirmation its person must give. */
    public static boolean agentConfirmationRequired(StepOutcome outcome) {
        return outcome.httpStatus() != null && outcome.httpStatus() == 403
                && AGENT_CONFIRMATION_REQUIRED.equals(outcome.ruleId());
    }

    /**
     * docs/agent A7-3: a confirmation as the engine's confirmation API answers its agent (A5-2).
     *
     * @param httpStatus      the API's answer; the other fields are null unless 200
     * @param status          PENDING, APPROVED, REJECTED, USED, EXPIRED or REPORTED
     * @param authorizationId the authorization record of an approved (or used) confirmation
     */
    public record AgentConfirmationStatus(int httpStatus, String status, String authorizationId, String expiresAt,
                                          String decidedAt, String trigger, String method, String target) {
    }

    /**
     * docs/agent A7-3: what became of a confirmation control D asked of an agent's request: the delegating person's
     * answer and what the engine did with the request sent again. Times are instants so they line up with the steps.
     *
     * @param decision     APPROVE or REJECT; null when the person gave none
     * @param reason       NOT_ASKED, EXPIRED, ABANDONED, or what failed; null when the confirmation was answered
     * @param decideStatus the confirmation page's answer to the person's decision; null without one
     * @param after        the confirmation as the agent read it after the decision
     * @param resend       the confirmed request sent again with the confirmation
     * @param reuse        the same request sent once more with the same confirmation (a second use)
     * @param other        another request sent with the same confirmation
     */
    public record AgentConfirmationTrace(String confirmationId, String trigger, String expiresAt, String decision,
                                         String reason, Instant askedAt, Instant decidedAt, Integer decideStatus,
                                         AgentConfirmationStatus after, StepOutcome resend, StepOutcome reuse,
                                         StepOutcome other, StepOutcome personRequest, RetryStorm retries) {

        /** A confirmation nobody was asked to answer (a recording without a delegating person's decision). */
        public static AgentConfirmationTrace notAsked(String confirmationId, String trigger, String expiresAt,
                                                      Instant askedAt) {
            return new AgentConfirmationTrace(confirmationId, trigger, expiresAt, null, "NOT_ASKED", askedAt, null,
                    null, null, null, null, null, null, null);
        }

        /** The person gave no answer: EXPIRED or ABANDONED. */
        public AgentConfirmationTrace unanswered(String why) {
            return new AgentConfirmationTrace(confirmationId, trigger, expiresAt, null, why, askedAt, null, null, null,
                    null, null, null, null, null);
        }
    }

    /**
     * docs/agent DD-27 (A5-7): the agent's request sent again and again at once while its confirmation waits, then
     * once more after the wait control D's call limit answer asked for.
     *
     * @param sent           how many times the request was sent at once
     * @param outcomes       how many of those answers came with each HTTP status and rule, as "429 AGENT_CALL_LIMIT"
     * @param firstLimitedAt which of them (from 1) first got the call limit's answer; null if none did
     * @param firstLimited   that answer
     * @param waitedSeconds  how long the agent then waited: the last limit answer's retryAfterSeconds
     * @param afterWait      the answer to the request sent after the wait; null without a limit answer
     */
    public record RetryStorm(int sent, Map<String, Integer> outcomes, Integer firstLimitedAt, StepOutcome firstLimited,
                             Long waitedSeconds, StepOutcome afterWait) {
    }

    /**
     * docs/agent A7-3: the actions on a confirmation of an agent's request, this session being the agent's: the person
     * answers in the person's own session of control D, the agent reads it and sends the request again with it.
     *
     * @param person       the delegating person's session of control D
     * @param otherPath    another request the agent sends with the same confirmation
     * @param companyTime  the company time the actions happen at
     */
    public AgentConfirmationActions agentConfirmationActions(String confirmationId, BusinessOperation operation,
                                                             String path, ControlSession person,
                                                             BusinessOperation otherOperation, String otherPath,
                                                             Supplier<Instant> companyTime) {
        String encoded = URLEncoder.encode(confirmationId, StandardCharsets.UTF_8);
        RequestParts confirmed = new RequestParts(null, Map.of(AGENT_CONFIRMATION_HEADER, confirmationId));
        return new AgentConfirmationActions() {
            @Override
            public int decide(DelegatorAnswer answer) throws IOException {
                return person.client.postForm("/contexa/agent-confirmations/" + encoded + answer.pagePath(),
                        UUID.randomUUID().toString(), companyTime.get(),
                        Map.of("note", "Answered in the showcase as the delegating employee")).status();
            }

            @Override
            public AgentConfirmationStatus status() throws IOException {
                Response response = client.get("/contexa/api/agent-confirmations/" + encoded,
                        UUID.randomUUID().toString(), companyTime.get());
                if (response.status() != 200) {
                    return new AgentConfirmationStatus(response.status(), null, null, null, null, null, null, null);
                }
                JsonNode node = json.readTree(response.body());
                return new AgentConfirmationStatus(200, textOrNull(node, "status"), textOrNull(node, "authorizationId"),
                        textOrNull(node, "expiresAt"), textOrNull(node, "decidedAt"), textOrNull(node, "trigger"),
                        textOrNull(node, "method"), textOrNull(node, "target"));
            }

            @Override
            public StepOutcome resend() throws IOException {
                return send(operation, path, companyTime.get(), confirmed, SendListener.NONE);
            }

            @Override
            public StepOutcome resendOther() throws IOException {
                return send(otherOperation, otherPath, companyTime.get(), confirmed, SendListener.NONE);
            }

            @Override
            public StepOutcome retry() throws IOException {
                return send(operation, path, companyTime.get(), RequestParts.NONE, SendListener.NONE);
            }

            @Override
            public StepOutcome personRequest() throws IOException {
                return person.send(operation, path, companyTime.get(), RequestParts.NONE, SendListener.NONE);
            }
        };
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static String excerpt(String text) {
        return text == null || text.length() <= EXCERPT ? text : text.substring(0, EXCERPT);
    }
}
