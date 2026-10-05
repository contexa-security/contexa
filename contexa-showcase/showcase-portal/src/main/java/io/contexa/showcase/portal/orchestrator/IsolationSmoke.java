package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.StepSummary;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.template.CloneVerifier;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Isolation smoke test of plan section 7 (P1-BE-09), on the real engine. A baseline run of a normal scenario, a
 * threat run, failed sign-ins of another principal and ten other runs happen before the same normal scenario runs
 * again; the second run must see the same context as the first, mention no other run's principal and inherit no
 * other run's state. T6 is measured between two clones of the same template (the store-level equality of clone and
 * template is P1-BE-06).
 */
public class IsolationSmoke {

    public record TestResult(String test, boolean passed, String evidence) {
    }

    public record SmokeReport(List<TestResult> results, List<RunSummary> runs) {
    }

    static final String NORMAL = "S01";
    static final String THREAT = "S04";
    static final List<String> OTHER_RUNS = List.of("S02", "S05", "S06", "S07", "S08", "S02", "S05", "S06", "S07",
            "S08");

    private final RunOrchestrator orchestrator;
    private final ScenarioCatalog scenarios;
    private final WorkloadAdmin admin;
    private final CloneVerifier clones;
    private final ControlEndpoints endpoints;
    private final InternalContextSigner signer;
    private final ObjectMapper json;
    private final SecureRandom random = new SecureRandom();

    public IsolationSmoke(RunOrchestrator orchestrator, ScenarioCatalog scenarios, WorkloadAdmin admin,
                          CloneVerifier clones, ControlEndpoints endpoints, InternalContextSigner signer,
                          ObjectMapper json) {
        this.orchestrator = orchestrator;
        this.scenarios = scenarios;
        this.admin = admin;
        this.clones = clones;
        this.endpoints = endpoints;
        this.signer = signer;
        this.json = json;
    }

    public SmokeReport run() throws IOException {
        ScenarioDefinition normal = scenarios.find(NORMAL).orElseThrow();
        List<RunSummary> runs = new ArrayList<>();
        RunSummary first = orchestrator.run(normal);
        runs.add(first);
        RunSummary twin = orchestrator.run(normal);
        runs.add(twin);
        RunSummary threat = orchestrator.run(scenarios.find(THREAT).orElseThrow());
        runs.add(threat);
        String failedSignIns = failedSignIns(normal.protagonist(), 5);
        for (String key : OTHER_RUNS) {
            runs.add(orchestrator.run(scenarios.find(key).orElseThrow()));
        }
        RunSummary again = orchestrator.run(normal);
        runs.add(again);

        List<TestResult> results = new ArrayList<>();
        results.add(t1(again));
        results.add(t2(normal.protagonist()));
        results.add(new TestResult("T3", sameEngineActions(first, again) && completed(again),
                "threat run " + threat.runId() + " engine actions " + actions(threat) + "; normal run before "
                        + actions(first) + ", after " + actions(again)));
        results.add(t4(again, failedSignIns));
        results.add(t5(runs));
        results.addAll(samePromptContext("T6", "two clones of the same template, same request", first, twin));
        results.addAll(samePromptContext("T7", "same scenario before and after " + (runs.size() - 2)
                + " other runs", first, again));
        return new SmokeReport(results, runs);
    }

    /**
     * T6 and T7 on the first step's normalised prompt, which carries only the cloned template and the request; later
     * steps also carry the earlier steps' outcomes, which may legitimately differ between runs of a non-deterministic
     * model. The plan's test is exact equality; -SET tells whether the same evidence facts arrived in another order
     * and -DOCS whether the same documents were retrieved.
     */
    private List<TestResult> samePromptContext(String test, String description, RunSummary a, RunSummary b)
            throws IOException {
        Optional<String> left = firstPrompt(a);
        Optional<String> right = firstPrompt(b);
        String evidence = description + ": " + prompts(a) + " vs " + prompts(b);
        if (!completed(a) || !completed(b) || left.isEmpty() || right.isEmpty()) {
            String missing = evidence + "; first-step prompt not available";
            return List.of(new TestResult(test, false, missing), new TestResult(test + "-SET", false, missing),
                    new TestResult(test + "-DOCS", false, missing));
        }
        PromptComparison.Result comparison = PromptComparison.compare(left.get(), right.get());
        String detail = evidence + "; differing lines " + comparison.differingLabels();
        return List.of(new TestResult(test, comparison.identical(), detail),
                new TestResult(test + "-SET", comparison.sameEvidenceSet(),
                        detail + "; same evidence facts in any order: " + comparison.sameEvidenceSet()),
                new TestResult(test + "-DOCS", comparison.sameRetrievedDocuments(),
                        detail + "; same retrieved documents: " + comparison.sameRetrievedDocuments()));
    }

    private Optional<String> firstPrompt(RunSummary run) throws IOException {
        for (StepSummary step : run.steps()) {
            if (step.promptSha256() != null) {
                return admin.prompt(step.requestId());
            }
        }
        return Optional.empty();
    }

    /** T1: the later run triggers no escalation protection and runs under its own organization. */
    private TestResult t1(RunSummary run) throws IOException {
        JsonNode protection = admin.escalationProtection(run.principal());
        List<String> organizations = new ArrayList<>();
        for (StepSummary step : run.steps()) {
            String organization = metadata(step.requestId()).path("organizationId").asText(null);
            if (organization != null) {
                organizations.add(organization);
            }
        }
        boolean ownOrganization = !organizations.isEmpty()
                && organizations.stream().allMatch(run.organization()::equals);
        return new TestResult("T1", protection.isEmpty() && ownOrganization,
                "escalation protection events " + protection.size() + "; decision organizations " + organizations
                        + " (run " + run.organization() + ")");
    }

    /** T2: after all runs, a fresh clone still equals the stored template. */
    private TestResult t2(String employeeKey) throws IOException {
        List<CloneVerifier.CloneCheck> checks = clones.verify(employeeKey, 1);
        return new TestResult("T2", checks.stream().allMatch(CloneVerifier.CloneCheck::equal),
                "clone after the runs: " + checks);
    }

    /** T4: another principal's failed sign-ins are not counted for the later run. */
    private TestResult t4(RunSummary run, String failedSignIns) throws IOException {
        List<Integer> counts = new ArrayList<>();
        for (StepSummary step : run.steps()) {
            JsonNode metadata = metadata(step.requestId());
            if (metadata.has("failedLoginAttempts")) {
                counts.add(metadata.path("failedLoginAttempts").asInt());
            }
        }
        return new TestResult("T4", !counts.isEmpty() && counts.stream().allMatch(count -> count == 0),
                failedSignIns + "; later run failedLoginAttempts " + counts);
    }

    /** T5: no prompt of any run mentions another run's principal. */
    private TestResult t5(List<RunSummary> runs) {
        Map<String, List<String>> foreign = new LinkedHashMap<>();
        int prompts = 0;
        for (RunSummary run : runs) {
            for (StepSummary step : run.steps()) {
                if (step.promptSha256() != null) {
                    prompts++;
                }
                if (!step.foreignPrincipals().isEmpty()) {
                    foreign.put(run.runId() + "#" + step.stepNo(), step.foreignPrincipals());
                }
            }
        }
        return new TestResult("T5", foreign.isEmpty() && prompts > 0,
                prompts + " prompts scanned; foreign principals " + foreign);
    }

    private String failedSignIns(String employeeKey, int attempts) throws IOException {
        String hex = HexFormat.of().formatHex(bytes());
        String runId = "fail-run-" + hex;
        String username = "v" + hex + "-" + employeeKey;
        JsonNode employee = admin.employee(employeeKey);
        RunIdentity run = new RunIdentity(runId, "org-" + hex, "tenant-" + hex,
                RunOrchestrator.hostIn(employee.path("officeNetwork").asText(), 251), employee.path("usualDevice").asText());
        String password = "Fail-" + UUID.randomUUID() + "-Aa1";
        int refused = 0;
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
            WorkloadClient client = new WorkloadClient(endpoints.d(), signer, run, endpoints.requestTimeout());
            for (int i = 0; i < attempts; i++) {
                WorkloadClient.Response response = client.postJson("/api/mfa/login", UUID.randomUUID().toString(), null,
                        json.writeValueAsString(Map.of("username", username, "password", "wrong-" + i)));
                if (response.status() != 200) {
                    refused++;
                }
            }
        } finally {
            admin.deleteEnginePrincipal(runId, username);
            admin.deletePlainRun(runId);
        }
        return "principal " + username + " failed " + refused + "/" + attempts + " sign-ins";
    }

    private JsonNode metadata(String requestId) throws IOException {
        JsonNode records = admin.decision(requestId).path("records");
        if (!records.isArray() || records.isEmpty()) {
            return json.createObjectNode();
        }
        String text = records.get(0).path("metadataJson").asText(null);
        return text == null ? json.createObjectNode() : json.readTree(text);
    }

    private static boolean completed(RunSummary run) {
        return "COMPLETED".equals(run.status());
    }

    private static boolean sameEngineActions(RunSummary a, RunSummary b) {
        return completed(a) && completed(b) && actions(a).equals(actions(b));
    }

    private static List<String> actions(RunSummary run) {
        return run.steps().stream().map(StepSummary::engineAction).toList();
    }

    private static List<String> prompts(RunSummary run) {
        return run.steps().stream().map(StepSummary::promptSha256).toList();
    }

    private byte[] bytes() {
        byte[] bytes = new byte[6];
        random.nextBytes(bytes);
        return bytes;
    }
}
