package io.contexa.showcase.portal.template;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.business.work.BusinessOperation;
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
 * the company time of each activity. The engine learns only from ALLOW decisions, and any other decision (or an
 * unresolved analysis) restricts the principal, so the replay stops there. The attempt is kept when the requests
 * learned before the stop already establish the baseline (ADR-23 thresholds); otherwise a new principal starts over
 * (at most three attempts). The finished state is read through the engine's public stores and kept in the portal
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
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            String templateId = "tpl-" + employeeKey + "-" + ID_TIME.format(Instant.now()) + "-" + attempt;
            templates.start(templateId, employeeKey, company.path("seed").asLong(),
                    LocalDate.parse(company.path("anchorDate").asText()), company.path("dataSha256").asText(), attempt,
                    engine.path("chatModel").asText(null), engine.path("embeddingModel").asText(null));
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
        RunIdentity run = new RunIdentity(runId, "org-tpl-" + hex, "tenant-tpl-" + hex,
                hostIn(employee.path("officeNetwork").asText(), 10), employee.path("usualDevice").asText());
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
            JsonNode activities = employee.path("scriptedActivities");
            Instant firstActivity = Instant.parse(activities.get(0).path("observedAt").asText());
            session.signInEngine(username, password, username + "@" + CompanyBlueprint.EMAIL_DOMAIN,
                    firstActivity.minus(Duration.ofMinutes(10)), admin);
            int allowed = 0;
            Integer stoppedAt = null;
            String stopReason = null;
            Set<String> learnedDays = new TreeSet<>();
            for (JsonNode activity : activities) {
                BusinessOperation operation = BusinessOperation.valueOf(activity.path("operation").asText());
                String target = activity.path("targetKey").asText();
                Instant at = Instant.parse(activity.path("observedAt").asText());
                String path = switch (operation) {
                    case DOCUMENT_READ -> "/api/documents/" + target;
                    case DOCUMENT_DOWNLOAD -> "/api/documents/" + target + "/download";
                    case EXPORT -> "/api/projects/" + target + "/exports?items=" + activity.path("items").asInt();
                    default -> throw new IllegalStateException("Unsupported scripted operation " + operation);
                };
                long waitStarted = System.nanoTime();
                StepOutcome outcome = session.send(operation, path, at);
                EngineDecision decision = waitForDecision(outcome.requestId(), operation == BusinessOperation.EXPORT);
                long waited = (System.nanoTime() - waitStarted) / 1_000_000L;
                templates.step(templateId, activity.path("activityNo").asInt(), outcome.requestId(), operation.name(),
                        target, at, outcome.httpStatus(), decision.finalAction(), decision.technicalFallback(),
                        decision.unresolved(), waited);
                for (JsonNode call : decision.raw().path("modelCalls")) {
                    runs.cost(null, templateId, outcome.requestId(), call);
                }
                if (!"DELIVERED".equals(outcome.outcome()) || !"ALLOW".equals(decision.finalAction())
                        || decision.unresolved()) {
                    stoppedAt = activity.path("activityNo").asInt();
                    stopReason = "Activity " + stoppedAt + " received " + decision.finalAction() + " (http "
                            + outcome.httpStatus() + ", unresolved " + decision.unresolved() + ", failure "
                            + decision.failureType() + ")";
                    break;
                }
                allowed++;
                learnedDays.add(at.toString().substring(0, 10));
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
