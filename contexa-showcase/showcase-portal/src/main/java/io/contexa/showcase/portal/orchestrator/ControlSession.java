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
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

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

    private final Control control;
    private final WorkloadClient client;
    private final ObjectMapper json;

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

    /** True when control D answered the step with the engine's additional check (401 MFA_CHALLENGE_REQUIRED). */
    public static boolean challenged(StepOutcome outcome) {
        return outcome.httpStatus() != null && outcome.httpStatus() == 401
                && "MFA_CHALLENGE_REQUIRED".equals(outcome.ruleId());
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
                return send(operation, path, companyTime);
            }
        };
    }

    public StepOutcome send(BusinessOperation operation, String path, Instant companyTime) throws IOException {
        String requestId = UUID.randomUUID().toString();
        return switch (operation) {
            case EXPORT, ROLE_GRANT -> outcome(requestId, "POST", path, companyTime,
                    client.postJson(path, requestId, companyTime, null), operation);
            case EXPORT_STREAM -> stream(requestId, path, companyTime);
            default -> outcome(requestId, "GET", path, companyTime, client.get(path, requestId, companyTime), operation);
        };
    }

    private StepOutcome outcome(String requestId, String method, String path, Instant companyTime, Response response,
                                BusinessOperation operation) {
        int status = response.status();
        String text = response.text();
        String outcome;
        int delivered = 0;
        String rule = null;
        String reason = null;
        if (status == 200) {
            outcome = "DELIVERED";
            delivered = operation == BusinessOperation.EXPORT ? jsonInt(text, "deliveredItems") : 1;
            if (operation == BusinessOperation.PROJECT_LIST) {
                delivered = 1;
            }
        } else if (status == 404) {
            outcome = "NOT_FOUND";
        } else if (status == 401 || status == 403 || status == 423) {
            outcome = "REFUSED";
            JsonNode body = jsonOrNull(text);
            if (body != null) {
                rule = textOrNull(body, "rule");
                if (rule == null) {
                    rule = textOrNull(body, "error");
                }
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
     * Reads a streamed export to the end or to the engine's cut. The outcome is CUT only when the engine wrote its
     * marker; a stream that breaks or ends short without it is an ERROR (deck p.11, P3-BE-02).
     */
    private StepOutcome stream(String requestId, String path, Instant companyTime) throws IOException {
        Instant sentAt = Instant.now();
        long started = System.nanoTime();
        HttpResponse<InputStream> response = client.openStream(path, requestId, companyTime);
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
                () -> (System.nanoTime() - started) / 1_000_000L);
        Progress progress = reading.progress();
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

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static String excerpt(String text) {
        return text == null || text.length() <= EXCERPT ? text : text.substring(0, EXCERPT);
    }
}
