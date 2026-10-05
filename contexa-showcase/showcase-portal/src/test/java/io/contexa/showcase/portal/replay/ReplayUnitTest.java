package io.contexa.showcase.portal.replay;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.StepSummary;
import io.contexa.showcase.portal.replay.ReplayStore.ArmRow;
import io.contexa.showcase.portal.replay.ReplayStore.DecisionRow;
import io.contexa.showcase.portal.replay.ReplayView.Layer;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Pair catalog, outcome signatures and the layer mapping of the visitor view, without a database. */
class ReplayUnitTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    @Test
    void thePackagedPairsNameKnownScenariosAndSteps() throws Exception {
        PairCatalog catalog = new PairCatalog(json, new ScenarioCatalog(json));

        PairDefinition a3 = catalog.find("A3").orElseThrow();
        assertThat(a3.scene(PairDefinition.SceneKind.ATTACK).scenario()).isEqualTo("A3");
        assertThat(a3.scene(PairDefinition.SceneKind.LEGITIMATE).scenario()).isEqualTo("A3T");
        assertThat(catalog.all()).extracting(PairDefinition::key).contains("A3");
    }

    @Test
    void aPairNamingAnUnknownScenarioOrStepIsRefused() throws Exception {
        ScenarioCatalog scenarios = new ScenarioCatalog(json);
        Map<String, String> words = Map.of("ko", "x", "en", "x");

        PairDefinition unknown = new PairDefinition("ZZ", 9, words, List.of(
                new PairDefinition.Scene(PairDefinition.SceneKind.ATTACK, "NOPE", words, 1),
                new PairDefinition.Scene(PairDefinition.SceneKind.LEGITIMATE, "A3T", words, 1)));
        PairDefinition missingStep = new PairDefinition("ZZ", 9, words, List.of(
                new PairDefinition.Scene(PairDefinition.SceneKind.ATTACK, "A3", words, 2),
                new PairDefinition.Scene(PairDefinition.SceneKind.LEGITIMATE, "A3T", words, 1)));

        assertThatThrownBy(() -> PairCatalog.validate(unknown, scenarios)).hasMessageContaining("unknown scenario");
        assertThatThrownBy(() -> PairCatalog.validate(missingStep, scenarios)).hasMessageContaining("features step 2");
    }

    @Test
    void signaturesIgnoreIdentityAndTheModeCountsAgreeingRuns() {
        RunSummary first = run("run-1", "ALLOW");
        RunSummary second = run("run-2", "ALLOW");
        RunSummary third = run("run-3", "CHALLENGE");

        String a = OutcomeSignature.of(first);
        assertThat(a).isEqualTo(OutcomeSignature.of(second)).isNotEqualTo(OutcomeSignature.of(third))
                .contains("1:A=DELIVERED,B=DELIVERED,C1=REFUSED,C2=REFUSED,D=DELIVERED,engine=ALLOW");

        OutcomeSignature.Mode mode = OutcomeSignature.mode(List.of(OutcomeSignature.of(third), a, a));
        assertThat(mode.signature()).isEqualTo(a);
        assertThat(mode.agreeing()).isEqualTo(2);
        assertThat(mode.repetitions()).isEqualTo(3);
        assertThat(OutcomeSignature.mode(List.of("x", "y")).signature()).as("the earliest on a tie").isEqualTo("x");
    }

    @Test
    void ruleControlsShowTheirResponseAndTheEngineCountsOnlyItsOwnDecisions() {
        Layer refused = ReplayViews.ruleLayer(arm("C1", 403, "REFUSED", "C1-NIGHT"), null, json);
        assertThat(refused.outcome()).isEqualTo("STOPPED");
        assertThat(refused.verdict()).isEqualTo("BLOCK");
        assertThat(refused.ruleId()).isEqualTo("C1-NIGHT");

        Layer granted = ReplayViews.ruleLayer(arm("B", 200, "DELIVERED", null), json.createObjectNode()
                .put("rule_id", "RBAC").put("reason", "Role ADMIN holds EXPORT").put("facts", "{\"role\": \"ADMIN\"}"),
                json);
        assertThat(granted.ruleId()).as("the control's own decision record").isEqualTo("RBAC");
        assertThat(granted.ruleFacts()).containsEntry("role", "ADMIN");

        Layer allowed = ReplayViews.engineLayer(arm("D", 200, "DELIVERED", null),
                Optional.of(decision("ALLOW", false, "NEXT_REQUEST")));
        assertThat(allowed.verdict()).isEqualTo("ALLOW");
        assertThat(allowed.evidence().decisionId()).isEqualTo("decision-1");
        assertThat(allowed.evidence().timing()).isEqualTo("NEXT_REQUEST");

        Layer unresolved = ReplayViews.engineLayer(arm("D", 200, "DELIVERED", null),
                Optional.of(decision("CHALLENGE", true, "NEXT_REQUEST")));
        assertThat(unresolved.verdict()).as("a technical fallback is not a verdict").isEqualTo("PENDING");

        Layer held = ReplayViews.engineLayer(arm("D", 401, "REFUSED", null),
                Optional.of(decision("CHALLENGE", false, "BEFORE_RESPONSE")));
        assertThat(held.outcome()).isEqualTo("HELD");

        Layer staticRefusal = ReplayViews.engineLayer(arm("D", 403, "REFUSED", null), Optional.empty());
        assertThat(staticRefusal.verdict()).isEqualTo("BLOCK");
        assertThat(staticRefusal.evidence().decisionId()).as("a 403 without an engine decision").isNull();
        assertThat(staticRefusal.evidence().timing()).isEqualTo("STATIC_AUTHORIZATION");
    }

    /** P3-BE-03: every timeline value is the stored event time minus the stored send time, in milliseconds. */
    @Test
    void theTimelineIsComputedFromTheStoredTimes() throws Exception {
        String events = "[{\"type\": \"CONTEXT_COLLECTED\", \"observedAt\": \"2026-10-05T02:56:35.092067700Z\"},"
                + "{\"type\": \"LAYER1_COMPLETE\", \"layer\": \"LAYER1\", \"action\": \"ALLOW\", \"elapsedMs\": 1808,"
                + " \"observedAt\": \"2026-10-05T02:56:36.900493800Z\"}, {\"type\": \"NO_TIME\"}]";

        List<ReplayView.TimelineEvent> timeline = ReplayViews.timeline(Instant.parse("2026-10-05T02:56:35.000Z"),
                json.readTree(events));

        assertThat(timeline).extracting(ReplayView.TimelineEvent::type).containsExactly("CONTEXT_COLLECTED",
                "LAYER1_COMPLETE");
        assertThat(timeline.get(0).atMs()).isEqualTo(92);
        assertThat(timeline.get(1).atMs()).isEqualTo(1900);
        assertThat(timeline.get(1).elapsedMs()).isEqualTo(1808);
        assertThat(timeline.get(1).action()).isEqualTo("ALLOW");
    }

    /** Deck p.11: a cut stream keeps its exposure, and the engine's decision shows as applied mid-response. */
    @Test
    void aCutStreamShowsItsExposureAndTheDecisionAppliedMidResponse() throws Exception {
        ArmRow cut = new ArmRow("D", "request-D", "EXPORT_STREAM", "GET", "/api/projects/GB-500/exports/stream", 200,
                "CUT", 412, "ENGINE_CUT", "BLOCK", 2610L, null, Instant.parse("2026-10-05T02:56:35.000Z"),
                json.readTree("{\"total\": 4831, \"delivered\": 412, \"firstLineMs\": 38, \"endMs\": 2610,"
                        + " \"cut\": \"BLOCK\", \"interrupted\": false, \"samples\": [[38, 1], [140, 17], [2610, 412]]}"));

        Layer layer = ReplayViews.engineLayer(cut, Optional.of(decision("BLOCK", false, "NEXT_REQUEST")));

        assertThat(layer.outcome()).isEqualTo("CUT");
        assertThat(layer.verdict()).isEqualTo("BLOCK");
        assertThat(layer.evidence().timing()).isEqualTo("MID_RESPONSE");
        ReplayView.Stream stream = layer.evidence().stream();
        assertThat(stream.cut()).isTrue();
        assertThat(stream.total()).isEqualTo(4831);
        assertThat(stream.delivered()).isEqualTo(412);
        assertThat(stream.samples()).hasSize(3);
        assertThat(stream.samples().get(2)).containsExactly(2610L, 412L);
        assertThat(ReplayViews.ruleLayer(arm("C1", 403, "REFUSED", "C1-NIGHT"), null, json).evidence().stream())
                .isNull();
    }

    @Test
    void companyFactsAreReadFromTheContextControlsLookup() throws Exception {
        ReplayViews views = new ReplayViews(null, null, json);
        String facts = "{\"items\": 4831, \"approval\": {\"covered\": false}, \"ticket\": {\"covered\": false},"
                + " \"assigned\": {\"assigned\": false}, \"projectKey\": \"GB-500\", \"accessDaysLast30\": 0,"
                + " \"oncall\": {\"onCall\": false}, \"network\": {\"kind\": \"TRAVEL\", \"city\": \"Singapore\"},"
                + " \"claim\": {\"ticketKey\": \"INC-7781\", \"exists\": false, \"coverage\": {\"covered\": false}}}";

        List<ReplayView.Fact> read = views.companyFacts(json.readTree(json.writeValueAsString(Map.of("facts", facts))));

        assertThat(read).extracting(ReplayView.Fact::code).containsExactly("NOT_ASSIGNED", "NO_APPROVAL", "NO_TICKET",
                "NOT_ON_CALL", "ACCESS_DAYS_LAST_30", "ITEMS", "NETWORK_TRAVEL", "CLAIM_NOT_CONFIRMED");
        assertThat(read.get(6).value()).isEqualTo("Singapore");
        assertThat(read.get(0).value()).isEqualTo("GB-500");
    }

    @Test
    void theEngineReasonIsCanonicalOnlyWhenItIsExactlyAContractSentence() throws Exception {
        ReplayViews views = new ReplayViews(null, null, json);
        String metadata = json.writeValueAsString(Map.of("evidenceRefs", List.of("baseline", "authorization"),
                "strongestCurrentRequestCombinationDelta", "closestOverlap=3/6 | differing=accessHour, pathFamily",
                "resourceSensitivity", "RESTRICTED"));
        String sentence = "Authorization allows access, the personal baseline is established, and authorized RAG is "
                + "relevant to the same resource.";

        ReplayView.EngineReason canonical = views.engineReason(Optional.of(decisionWith(sentence, metadata)));
        ReplayView.EngineReason free = views.engineReason(Optional.of(decisionWith("Something else.", metadata)));

        assertThat(canonical.canonical()).isEqualTo("ALLOW_BASELINE_SAME_RESOURCE_HISTORY");
        assertThat(canonical.evidenceRefs()).containsExactly("baseline", "authorization");
        assertThat(canonical.deltas()).containsExactly("accessHour", "pathFamily");
        assertThat(canonical.resourceSensitivity()).isEqualTo("RESTRICTED");
        assertThat(free.canonical()).isNull();
        assertThat(free.reasoning()).isEqualTo("Something else.");
    }

    private static RunSummary run(String runId, String engine) {
        return new RunSummary(runId, "A3", "v" + runId, "org-" + runId, "COMPLETED", null, List.of(
                new StepSummary(1, "EXPORT", "/api/projects/GB-500/exports",
                        Map.of("A", "DELIVERED", "B", "DELIVERED", "C1", "REFUSED", "C2", "REFUSED", "D", "DELIVERED"),
                        Map.of(), true, engine, "NEXT_REQUEST", false, "request-" + runId, "hash-" + runId,
                        List.of(), null)));
    }

    private static ArmRow arm(String control, int status, String outcome, String ruleId) {
        return new ArmRow(control, "request-" + control, "EXPORT", "POST", "/api/projects/GB-500/exports", status,
                outcome, "DELIVERED".equals(outcome) ? 4831 : 0, ruleId, ruleId == null ? null : "reason", 12L, null,
                Instant.parse("2026-10-05T02:56:35.000Z"), null);
    }

    private DecisionRow decision(String action, boolean unresolved, String applied) {
        return new DecisionRow("decision-1", action, action, 0.2, 0.6, unresolved, unresolved, "text", applied, 1500L,
                null, json.createArrayNode(), json.createArrayNode());
    }

    private DecisionRow decisionWith(String reasoning, String metadata) {
        return new DecisionRow("decision-1", "ALLOW", "ALLOW", 0.2, 0.6, false, false, reasoning, "NEXT_REQUEST",
                1500L, null, json.createArrayNode().add(json.createObjectNode().put("metadataJson", metadata)),
                json.createArrayNode());
    }
}
