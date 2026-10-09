package io.contexa.showcase.portal.template;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.spec.ExecutionSpecStore;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.orchestrator.ChallengeResponder;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.orchestrator.ControlSession;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;
import io.contexa.showcase.portal.orchestrator.EngineDecision;
import io.contexa.showcase.portal.orchestrator.RunStore;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Learns a protagonist's template through the engine's own learning path (deck p.26 principle 1, ADR-23): a fresh
 * template principal signs in for real and replays the employee's scripted normal activity as real requests, with
 * the company time of each activity. The engine learns only from ALLOW decisions. When it asks for an identity check,
 * the employee passes it with the code from the demo inbox and sends the same request again, as a real employee would
 * (approval Q-43); that step is kept with the check and is not counted as learned. Any other restriction (BLOCK,
 * ESCALATE) or an unresolved analysis stops the replay. The attempt is kept when the requests learned before the stop
 * already establish the baseline (ADR-23 thresholds); otherwise a new principal starts over (at most three attempts). The finished state is read through the engine's public stores and kept in the portal
 * database.
 */
public class TemplateLearner {

    private static final Logger log = LoggerFactory.getLogger(TemplateLearner.class);

    static final int MAX_ATTEMPTS = 3;
    static final long MIN_BASELINE_UPDATES = 20;
    static final int MIN_WORK_PROFILE_OBSERVATIONS = 3;
    static final int MIN_LEARNED_DAYS = 2;
    static final Duration LEARNING_SETTLE = Duration.ofSeconds(90);
    static final DateTimeFormatter ID_TIME = DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC);

    private final ControlEndpoints endpoints;
    private final WorkloadAdmin admin;
    private final InternalContextSigner signer;
    private final TemplateStore templates;
    private final RunStore runs;
    private final ObjectMapper json;
    private final SecureRandom random = new SecureRandom();

    public TemplateLearner(ControlEndpoints endpoints, WorkloadAdmin admin, InternalContextSigner signer,
                           TemplateStore templates, RunStore runs, ObjectMapper json) {
        this.endpoints = endpoints;
        this.admin = admin;
        this.signer = signer;
        this.templates = templates;
        this.runs = runs;
        this.json = json;
    }

    /** Returns the READY template id, or null when every attempt failed. */
    public String learn(String employeeKey) throws IOException {
        JsonNode company = admin.company();
        JsonNode employee = admin.employee(employeeKey);
        JsonNode engine = admin.engine();
        String learnedUnder = TemplateVersions.key(engine, company);
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            String templateId = "tpl-" + employeeKey + "-" + ID_TIME.format(Instant.now()) + "-" + attempt;
            templates.start(templateId, employeeKey, company.path("seed").asLong(),
                    LocalDate.parse(company.path("anchorDate").asText()), company.path("dataSha256").asText(), attempt,
                    engine.path("chatModel").asText(null), engine.path("embeddingModel").asText(null), learnedUnder,
                    ExecutionSpecStore.modelSettings(engine));
            String failure = attempt(templateId, employeeKey, employee);
            if (failure == null) {
                return templateId;
            }
            templates.failed(templateId, failure);
        }
        return null;
    }

    private String attempt(String templateId, String employeeKey, JsonNode employee) {
        String hex = HexFormat.of().formatHex(randomBytes(6));
        String runId = "tpl-run-" + hex;
        String username = "v" + hex + "-" + employeeKey;
        String password = "Template-" + UUID.randomUUID() + "-Aa1";
        JsonNode activities = employee.path("scriptedActivities");
        RunIdentity run = new RunIdentity(runId, "org-tpl-" + hex, "tenant-tpl-" + hex,
                addressOf(activities.get(0), employee), employee.path("usualDevice").asText());
        try {
            admin.registerPlainPrincipal(run, username, password, employeeKey);
            Map<String, Object> principal = new LinkedHashMap<>();
            principal.put("username", username);
            principal.put("password", password);
            principal.put("employeeKey", employeeKey);
            principal.put("roleKey", employee.path("roleKey").asText());
            principal.put("displayName", employee.path("displayName").asText());
            principal.put("department", employee.path("department").asText());
            principal.put("organizationId", run.organization());
            principal.put("tenantId", run.tenant());
            admin.createEnginePrincipal(run, principal);
            ControlSession session = new ControlSession(Control.D,
                    new WorkloadClient(endpoints.d(), signer, run, endpoints.requestTimeout()), json);
            Instant firstActivity = Instant.parse(activities.get(0).path("observedAt").asText());
            session.signInEngine(username, password, username + "@" + CompanyBlueprint.EMAIL_DOMAIN,
                    firstActivity.minus(Duration.ofMinutes(10)), admin);
            int allowed = 0;
            Integer stoppedAt = null;
            String stopReason = null;
            Set<String> learnedDays = new TreeSet<>();
            String email = username + "@" + CompanyBlueprint.EMAIL_DOMAIN;
            for (JsonNode activity : activities) {
                int activityNo = activity.path("activityNo").asInt();
                BusinessOperation operation = BusinessOperation.valueOf(activity.path("operation").asText());
                String target = activity.path("targetKey").asText();
                Instant at = Instant.parse(activity.path("observedAt").asText());
                String path = path(operation, target, activity.path("items").asInt());
                boolean synchronous = EngineDecision.synchronous(operation);
                // Each activity comes from the address the business database names for it (W2-7), in the same session.
                ControlSession from = session.fromAddress(addressOf(activity, employee));
                long waitStarted = System.nanoTime();
                StepOutcome outcome = from.send(operation, path, at);
                boolean challenged = ControlSession.challenged(outcome);
                // A request refused by an earlier CHALLENGE is never analysed, so it has no decision of its own.
                EngineDecision decision = challenged && !synchronous
                        ? EngineDecision.none(admin.decision(outcome.requestId()))
                        : waitForDecision(outcome.requestId(), synchronous);
                long waited = (System.nanoTime() - waitStarted) / 1_000_000L;
                templates.step(templateId, activityNo, outcome.requestId(), operation.name(), target, at,
                        outcome.httpStatus(), decision.finalAction(), decision.technicalFallback(),
                        decision.unresolved(), waited);
                for (JsonNode call : decision.raw().path("modelCalls")) {
                    runs.cost(null, templateId, outcome.requestId(), call);
                }
                ControlSession.ChallengeTrace check = null;
                if (challenged) {
                    // The employee passes the engine's identity check with the code from the demo inbox and sends
                    // the same request again (approval Q-43); the engine's decision itself is left as it was.
                    check = ChallengeResponder.AUTOMATIC.respond(new ChallengeResponder.Challenge("NORMAL",
                            outcome.sentAt().plusMillis(outcome.elapsedMs()),
                            from.challengeActions(username, email, operation, path, at, admin)));
                    templates.identityCheck(templateId, activityNo, check);
                }
                Next next = next("DELIVERED".equals(outcome.outcome()), challenged, decision.finalAction(),
                        decision.unresolved(), check);
                if (next == Next.STOP) {
                    stoppedAt = activityNo;
                    stopReason = "Activity " + stoppedAt + " received " + decision.finalAction() + " (http "
                            + outcome.httpStatus() + ", unresolved " + decision.unresolved() + ", failure "
                            + decision.failureType()
                            + (check == null ? "" : ", identity check " + (check.answered() ? "answered" : "not "
                            + "answered: " + check.reason()) + ", re-issued " + (check.reissue() == null ? "none"
                            : check.reissue().httpStatus() + " " + check.reissue().outcome())) + ")";
                    break;
                }
                if (next == Next.LEARNED) {
                    allowed++;
                    learnedDays.add(at.toString().substring(0, 10));
                }
                sleep(endpoints.allowWindow());
            }
            if (allowed < MIN_BASELINE_UPDATES || learnedDays.size() < MIN_LEARNED_DAYS) {
                return (stopReason == null ? "Replay ended" : stopReason) + " with " + allowed
                        + " learned requests on " + learnedDays.size() + " days";
            }
            JsonNode snapshot = settledSnapshot(username, employeeKey, run, allowed);
            long updates = snapshot.path("baselineUpdateCount").asLong();
            int observations = snapshot.path("workProfileObservations").size();
            if (updates < MIN_BASELINE_UPDATES || observations < MIN_WORK_PROFILE_OBSERVATIONS) {
                return "Learned state too thin: baselineUpdateCount=" + updates + ", workProfileObservations="
                        + observations;
            }
            templates.ready(templateId, snapshot, stoppedAt);
            for (JsonNode call : admin.embeddings(username)) {
                runs.cost(null, templateId, null, call);
            }
            return null;
        } catch (IOException | RuntimeException e) {
            log.error("Template learning attempt failed: templateId={}", templateId, e);
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            try {
                admin.deleteEnginePrincipal(runId, username);
                admin.deletePlainRun(runId);
            } catch (IOException | RuntimeException e) {
                log.error("Template principal cleanup failed: templateId={}", templateId, e);
            }
        }
    }

    /** What the replay does after one scripted activity. */
    enum Next {
        /** The engine allowed the request and learns it. */
        LEARNED,
        /** The engine asked for an identity check, the employee passed it and the re-issued request was delivered. */
        PASSED_CHECK,
        /** Delivered, but the engine decided CHALLENGE, which applies from the next request; it is not learned. */
        NOT_LEARNED,
        /** Anything else restricts the principal or leaves the engine undecided: the replay stops. */
        STOP
    }

    /**
     * The replay's rule (approval Q-43): an identity check the employee passes lets the replay go on, without counting
     * the step as learned, because the engine learns from ALLOW decisions only; BLOCK, ESCALATE, an unresolved analysis
     * or no decision stop it as before.
     */
    static Next next(boolean delivered, boolean challenged, String finalAction, boolean unresolved,
                     ControlSession.ChallengeTrace check) {
        if (challenged) {
            boolean passed = check != null && check.answered() && check.reissue() != null
                    && "DELIVERED".equals(check.reissue().outcome());
            return passed && !unresolved ? Next.PASSED_CHECK : Next.STOP;
        }
        if (!delivered || unresolved) {
            return Next.STOP;
        }
        if ("ALLOW".equals(finalAction)) {
            return Next.LEARNED;
        }
        return "CHALLENGE".equals(finalAction) ? Next.NOT_LEARNED : Next.STOP;
    }

    /** Baseline learning runs asynchronously after each ALLOW; wait until every allowed request has been learned. */
    private JsonNode settledSnapshot(String username, String employeeKey, RunIdentity run, int allowed)
            throws IOException {
        Instant deadline = Instant.now().plus(LEARNING_SETTLE);
        JsonNode snapshot;
        do {
            snapshot = admin.snapshot(username, employeeKey, run.organization(), run.tenant());
            if (snapshot.path("baselineUpdateCount").asLong() >= Math.min(allowed, MIN_BASELINE_UPDATES)) {
                sleep(Duration.ofSeconds(3));
                return admin.snapshot(username, employeeKey, run.organization(), run.tenant());
            }
            sleep(Duration.ofSeconds(2));
        } while (Instant.now().isBefore(deadline));
        return snapshot;
    }

    private EngineDecision waitForDecision(String requestId, boolean synchronous) throws IOException {
        Instant deadline = Instant.now().plus(endpoints.decisionWait());
        JsonNode evidence;
        do {
            evidence = admin.decision(requestId);
            EngineDecision decision = EngineDecision.from(evidence, synchronous);
            if (decision != null) {
                return decision;
            }
            sleep(Duration.ofSeconds(1));
        } while (Instant.now().isBefore(deadline));
        return EngineDecision.none(evidence);
    }

    /** The address an activity was sent from; the employee's desk in the office network when none is recorded. */
    /** The business API path a scripted activity is sent to. */
    public static String path(BusinessOperation operation, String target, int items) {
        return switch (operation) {
            case DOCUMENT_READ -> "/api/documents/" + target;
            case DOCUMENT_DOWNLOAD -> "/api/documents/" + target + "/download";
            case EXPORT -> "/api/projects/" + target + "/exports?items=" + items;
            default -> throw new IllegalStateException("Unsupported scripted operation " + operation);
        };
    }

    /** The address a scripted activity comes from: its own recorded address, or a host in the office network. */
    public static String addressOf(JsonNode activity, JsonNode employee) {
        String recorded = activity == null ? null : activity.path("clientIp").asText(null);
        return recorded != null && !recorded.isBlank() ? recorded
                : hostIn(employee.path("officeNetwork").asText(), 10);
    }

    static String hostIn(String network, int host) {
        return network.substring(0, network.lastIndexOf('.')) + "." + host;
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted", e);
        }
    }
}
