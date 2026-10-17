package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.portal.anatomy.AnatomyBuilder.StoredCall;
import io.contexa.showcase.portal.anatomy.AnatomyBuilder.StoredDecision;
import io.contexa.showcase.portal.anatomy.AnatomyBuilder.Surroundings;
import io.contexa.showcase.portal.scoring.RunScores.DecisionSource;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.RunScores.StepVerdict;
import io.contexa.showcase.portal.scoring.RunScores.TruthSource;
import io.contexa.showcase.portal.scoring.Scoring;
import io.contexa.showcase.portal.scoring.Scoring.VerdictResult;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * The anatomy is assembled from real stored records only (docs/showcase/데모-재설계.md 3, V-2, V-3). The samples in
 * test/resources/anatomy are two real decisions of the 2026-10-06 measurement (gpt-5-nano, reasoning effort low,
 * output limit 1024), extracted from the portal database and control D with the HTTP session identifiers masked. In
 * both runs the visitor path sent step 1 only, so the score is taken over one sent step.
 */
class AnatomyBuilderTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private final AnatomyBuilder builder = new AnatomyBuilder(JSON);

    @Test
    void anAttackTheModelChallengedShowsWhatTheEngineReceivedAndWhatTheModelAnswered() throws IOException {
        JsonNode sample = sample("a3s-challenge");
        DecisionAnatomy anatomy = build(sample);

        DecisionAnatomy.Context context = anatomy.context();
        assertThat(context.usualVsNow()).filteredOn(comparison -> comparison.dimension().equals("accessHour"))
                .singleElement().satisfies(hour -> {
                    assertThat(hour.now()).isEqualTo("3");
                    assertThat(hour.inUsual()).isEqualTo("false");
                });
        assertThat(context.resource()).containsEntry("sensitivity", "CRITICAL");
        assertThat(context.company()).containsEntry("approvalMissing", true);
        assertThat(context.session().toString()).as("the HTTP session identifier never leaves the portal")
                .doesNotContainPattern("\\b[0-9A-F]{32}\\b");

        DecisionAnatomy.Call call = anatomy.interpretation().calls().get(0);
        assertThat(call.requestOptions()).containsEntry("reasoning_effort", "low")
                .containsEntry("max_completion_tokens", 1024);
        assertThat(call.finishReason()).isEqualTo("stop");
        assertThat(call.reasoningTokens()).isPositive();
        assertThat(call.parsedAnswer()).containsEntry("action", "CHALLENGE");

        String modelReasoning = anatomy.interpretation().modelReasoning();
        assertThat(modelReasoning).startsWith("High-sensitivity access departs from the established personal baseline");
        assertThat(anatomy.interpretation().contractLines()).as("the sentence the system prompt prescribes")
                .anySatisfy(line -> assertThat(line).startsWith("5a.").contains(modelReasoning));
        assertThat(anatomy.interpretation().recorded().reasoningCode())
                .as("the recorded reasoning is the contract's fixed sentence of rule 5a")
                .isEqualTo("CHALLENGE_ELEVATED_RISK_BOUNDARY");
        // Content lines of the stored texts (D-38), counted apart by an independent script on the same record.
        assertThat(anatomy.promptLines().system()).isEqualTo(106);
        assertThat(anatomy.promptLines().user()).isEqualTo(226);
        assertThat(anatomy.promptLines().total()).isEqualTo(332);
        assertThat(anatomy.promptLines().systemPhysical()).as("lines as the opened text shows them").isEqualTo(118);
        // The work profile summary the engine received: "Window 7d | Observations 25 | ..." (T-27).
        assertThat(anatomy.figures().workProfileWindow()).isEqualTo("7d");
        assertThat(anatomy.figures().workProfileObservations()).isEqualTo(25);
        assertThat(anatomy.figures().departureCount()).as("the items rendered as not in the baseline")
                .isEqualTo(anatomy.juxtaposition().departures().size());
        assertThat(anatomy.promptLines().userPhysical()).isEqualTo(243);
        assertThat(anatomy.promptLines().layout()).as("a v19 prompt keeps its seven bundles (W3-10)")
                .isEqualTo(PromptLines.V19_SECTIONS);
        assertThat(anatomy.promptLines().sections()).hasSize(18)
                .noneMatch(section -> section.bundle().equals("OTHER"));
        assertThat(anatomy.promptLines().bundles()).containsExactly(new PromptLines.Bundle("RULES", 107),
                new PromptLines.Bundle("REQUEST", 30), new PromptLines.Bundle("IDENTITY", 23),
                new PromptLines.Bundle("USUAL", 87), new PromptLines.Bundle("HISTORY", 21),
                new PromptLines.Bundle("COMPANY", 7), new PromptLines.Bundle("UNKNOWN", 57),
                new PromptLines.Bundle("OTHER", 0));

        assertThat(anatomy.truth().classification()).isEqualTo("THREAT");
        assertThat(anatomy.truth().truthSource()).isEqualTo("RUN_SNAPSHOT");
        assertThat(anatomy.truth().verdict().score().result()).isEqualTo(VerdictResult.RIGHT);
        assertThat(anatomy.truth().verdict().score().applicable())
                .as("applied from the next request, and no request followed it in this run").isFalse();
        assertThat(anatomy.truth().verdict().source()).isEqualTo(DecisionSource.MODEL);

        assertThat(anatomy.interpretation().timeline()).extracting(DecisionAnatomy.TimelineEntry::kind,
                DecisionAnatomy.TimelineEntry::name).as("the call went out after Layer 1 started and was answered "
                        + "before Layer 1 completed").containsExactly(
                        tuple("EVENT", "CONTEXT_COLLECTED"), tuple("EVENT", "LAYER1_START"),
                        tuple("CALL_SENT", "call 1"), tuple("CALL_ANSWERED", "call 1"),
                        tuple("EVENT", "LAYER1_COMPLETE"), tuple("EVENT", "DECISION_APPLIED"));
        assertThat(call.sentAt()).isEqualTo(Instant.parse("2026-10-06T11:48:19.298083Z").minusMillis(4796));

        assertThat(anatomy.juxtaposition().departures()).extracting(DecisionAnatomy.Comparison::dimension)
                .contains("accessHour");
        assertThat(anatomy.juxtaposition().companyFacts())
                .anySatisfy(fact -> assertThat(fact).contains("requester assigned to project GB-500: no"));
        assertThat(anatomy.juxtaposition().sensitivity()).isEqualTo("CRITICAL");
        assertThat(anatomy.juxtaposition().coreAdverseLabels())
                .filteredOn(reading -> reading.label().equals("approvalmissing")).singleElement()
                .satisfies(reading -> {
                    assertThat(reading.values()).contains("true");
                    assertThat(reading.met()).as("the core inspector reads it as adverse evidence").isTrue();
                });
    }

    /**
     * 15.3 (S11): a run read back after a portal restart shows the decision's tokens as the live decision does, over
     * every model call; a call without a count adds nothing.
     */
    @Test
    void theTokensOfADecisionAreCountedOverEveryCall() {
        DecisionAnatomy.Interpretation interpretation = new DecisionAnatomy.Interpretation(
                List.of(call(1, 6_200L, 410L), call(2, 7_050L, null), call(3, null, 120L)), null, null, false, List.of(),
                null, List.of());

        assertThat(interpretation.promptTokens()).isEqualTo(13_250L);
        assertThat(interpretation.completionTokens()).isEqualTo(530L);
        assertThat(new DecisionAnatomy.Interpretation(null, null, null, false, List.of(), null, List.of()).promptTokens())
                .isZero();
    }

    private static DecisionAnatomy.Call call(int callNo, Long promptTokens, Long completionTokens) {
        return new DecisionAnatomy.Call(callNo, "model", Map.of(), "stop", promptTokens, completionTokens, null, null,
                true, null, null, null, null, 0, null, null, null);
    }

    /**
     * W3 (found while drafting the anatomy): the ground truth's rationale is given per language in the case; the
     * anatomy keeps both texts instead of reading the object as one empty text. A case without one gives none.
     */
    @Test
    void theRationaleOfTheGroundTruthIsKeptPerLanguage() throws IOException {
        JsonNode sample = sample("a3s-challenge");
        assertThat(build(sample).truth().rationale()).as("the sample case gives no rationale").isNull();
        assertThat(build(sample).truth().counterpoint()).isNull();

        ObjectNode oracle = (ObjectNode) sample.path("scenarioDefinition").path("oracle");
        oracle.putObject("rationale").put("ko", "설계된 공격").put("en", "Designed attack");
        oracle.putObject("counterpoint").put("ko", "반론").put("en", "Counterpoint");

        DecisionAnatomy.Truth truth = build(sample).truth();
        assertThat(truth.rationale()).containsExactly(Map.entry("ko", "설계된 공격"), Map.entry("en", "Designed attack"));
        assertThat(truth.counterpoint()).containsExactly(Map.entry("ko", "반론"), Map.entry("en", "Counterpoint"));
    }

    @Test
    void aTruncatedAnswerIsShownAsWhatHappenedNotAsAVerdict() throws IOException {
        DecisionAnatomy anatomy = build(sample("a3st-truncated"));

        DecisionAnatomy.Call call = anatomy.interpretation().calls().get(0);
        assertThat(call.finishReason()).as("the reasoning used the whole output limit").isEqualTo("length");
        assertThat(call.reasoningTokens()).isEqualTo(1024L);
        assertThat(call.parsedAnswer()).isNull();
        assertThat(anatomy.interpretation().modelReasoning()).isNull();
        assertThat(anatomy.interpretation().reasoningDiffers()).isFalse();
        assertThat(anatomy.interpretation().recorded().unresolved()).isTrue();
        assertThat(anatomy.truth().classification()).isEqualTo("NORMAL");
        assertThat(anatomy.truth().verdict().score().result()).as("a technical fallback is never a verdict")
                .isEqualTo(VerdictResult.UNRESOLVED);
        assertThat(anatomy.truth().verdict().source()).isEqualTo(DecisionSource.FALLBACK);
        assertThat(anatomy.interpretation().timeline()).filteredOn(entry -> "CALL_ANSWERED".equals(entry.kind()))
                .singleElement().satisfies(entry -> assertThat(entry.detail()).startsWith("length"));
    }

    @Test
    void theRecordsAroundTheDecisionAreCopiedAsTheyWereStored() throws IOException {
        Map<String, Object> challenge = Map.of("answered", true, "reissue_outcome", "DELIVERED");
        Map<String, Object> learning = Map.of("templateId", "tpl-x", "newBehaviourDocuments", List.of());
        DecisionAnatomy anatomy = build(sample("a3st-truncated"), Map.of("template_id", "tpl-x"), learning,
                challenge);

        assertThat(anatomy.recovery().challenge()).isEqualTo(challenge);
        assertThat(anatomy.recovery().release()).isNull();
        assertThat(anatomy.learning()).isEqualTo(learning);
        assertThat(anatomy.context().template()).containsEntry("template_id", "tpl-x");
        assertThat(build(sample("a3st-truncated")).recovery()).as("a step without a check or release").isNull();
    }

    @Test
    void contractLinesAreFoundInTheStoredPromptOnly() {
        String prompt = "rules\n2. If the chosen action is ALLOW, reasoning must be exactly \"A fixed sentence.\"\nend";
        assertThat(AnatomyBuilder.contractLines(prompt, "A fixed sentence.")).containsExactly(
                "2. If the chosen action is ALLOW, reasoning must be exactly \"A fixed sentence.\"");
        assertThat(AnatomyBuilder.contractLines(prompt, "A sentence of the model's own.")).isEmpty();
        assertThat(AnatomyBuilder.contractLines(null, "A fixed sentence.")).isEmpty();
    }

    /**
     * N-DEP-1 (W7-12 C-2): a v20 user prompt renders no label matrix, so the comparison is the one the engine sealed in
     * its decision facts, the computation the prompt's DeviationsFromBaseline and SameAsBaseline lines are drawn from.
     * Step 1 of the representative attack (anatomy/v20-deviations.json, run-3766bd77c869) states 4 of 10 compared, all
     * unexplained: time, target, class and size; the six others are as usual.
     */
    @Test
    void aV20DecisionIsComparedAsTheEngineSealedItsDeviations() throws IOException {
        DecisionAnatomy anatomy = v20(v20Decision("A3"));

        assertThat(anatomy.context().usualVsNow()).extracting(DecisionAnatomy.Comparison::dimension,
                DecisionAnatomy.Comparison::now, DecisionAnatomy.Comparison::inUsual).containsExactly(
                tuple("accessHour", "03", "false"), tuple("dayOfWeek", "Wed", "true"),
                tuple("network", "10.40.12.0/24", "true"), tuple("device", "Chrome/140 on WINDOWS", "true"),
                tuple("authenticationType", "PASSWORD+ONE_TIME_CODE", "true"), tuple("target", "projectKey", "false"),
                tuple("actionFamily", "EXPORT", "true"), tuple("resourceFamily", "CRITICAL", "false"),
                tuple("size", "4,831 items", "false"), tuple("rate", "1 requests in the last 60 min", "true"));
        assertThat(anatomy.juxtaposition().departures()).as("the dimensions the seal states as unexplained")
                .extracting(DecisionAnatomy.Comparison::dimension)
                .containsExactly("accessHour", "target", "resourceFamily", "size");
        assertThat(anatomy.juxtaposition().departures()).allSatisfy(departure -> assertThat(departure.labels())
                .containsExactly("DeviationsFromBaseline"));
        assertThat(anatomy.figures().departureCount()).isEqualTo(4);
        assertThat(anatomy.context().labelMatrix()).as("the v20 prompt rendered no label").isEmpty();
        assertThat(BeforeSend.sealedUsual(anatomy.context().usual()).keySet())
                .as("the comparison before sending has the usual of every dimension compared")
                .containsExactlyInAnyOrderElementsOf(anatomy.context().usualVsNow().stream()
                        .map(DecisionAnatomy.Comparison::dimension).toList());
    }

    /**
     * N-DEP-1: a difference a record explains is still a difference from the usual: the real employee's step 1
     * (run-f2855b9824ce) states the same four, each explained by the approval (design E2-2: the differences stay, the
     * company records no longer flag).
     */
    @Test
    void aDifferenceTheApprovalExplainsIsStillADeparture() throws IOException {
        DecisionAnatomy anatomy = v20(v20Decision("A3T"));

        assertThat(anatomy.juxtaposition().departures()).extracting(DecisionAnatomy.Comparison::dimension)
                .containsExactly("accessHour", "target", "resourceFamily", "size");
        assertThat(anatomy.figures().departureCount()).isEqualTo(4);
    }

    /** N-DEP-1: a dimension the engine could not compare is neither as usual nor a departure, with the engine's why. */
    @Test
    void aDimensionTheEngineDidNotCompareIsUnknownWithItsReason() {
        ObjectNode metadata = JSON.createObjectNode().put("userPromptLayoutVersion", "v20-dictionary-blocks");
        metadata.putObject("sealedEvidence.canonicalContext").putObject("decisionFacts").putArray("deviations")
                .addObject().put("dimension", "TARGET").put("current", "projectKey").put("compared", false)
                .put("different", false).put("explanation", "UNKNOWN")
                .put("notComparedReason", "no usual target of this kind");

        DecisionAnatomy anatomy = fromMetadata(metadata, null);

        assertThat(anatomy.context().usualVsNow()).singleElement().satisfies(target -> {
            assertThat(target.dimension()).isEqualTo("target");
            assertThat(target.inUsual()).isEqualTo("UNKNOWN - no usual target of this kind");
        });
        assertThat(anatomy.juxtaposition().departures()).isEmpty();
        assertThat(anatomy.figures().departureCount()).as("one dimension listed, none different").isZero();
    }

    /** N-DEP-1: a v19 record keeps the comparison of its label matrix, even with decision facts in its context. */
    @Test
    void aV19RecordKeepsItsLabelMatrix() throws IOException {
        JsonNode sample = sample("a3s-challenge");
        ObjectNode record = (ObjectNode) sample.path("decision").path("records").get(0);
        ObjectNode metadata = (ObjectNode) JSON.readTree(record.path("metadataJson").asText());
        JsonNode sealed = JSON.readTree(v20Decision("A3").path("records").get(0).path("metadataJson").asText());
        ((ObjectNode) metadata.path("sealedEvidence.canonicalContext")).set("decisionFacts",
                sealed.path("sealedEvidence.canonicalContext").path("decisionFacts"));
        record.put("metadataJson", metadata.toString());

        DecisionAnatomy anatomy = build(sample);

        assertThat(anatomy.context().usualVsNow()).extracting(DecisionAnatomy.Comparison::dimension)
                .as("the v19 labels").contains("accessHour", "pathFamily").doesNotContain("target", "size");
        assertThat(anatomy.figures().departureCount()).isEqualTo(3);
        assertThat(anatomy.juxtaposition().coreAdverseLabels()).as("the v19 inspector's labels, read from the prompt")
                .hasSize(CoreAdverseLabels.RULES.size());
    }

    /**
     * N-DEP-2 (W7-12 C-2): a v20 prompt renders none of the labels the core's v19 inspector reads, so the adverse
     * conditions are the core's v20 ones, read from the facts the engine sealed: the representative attack states its
     * company policy as not met (PolicySatisfied no) and nothing else of the list; the real employee's approval meets
     * it.
     */
    @Test
    void aV20DecisionsAdverseConditionsAreReadFromItsSealedFacts() throws IOException {
        DecisionAnatomy attack = v20(v20Decision("A3"));
        DecisionAnatomy owner = v20(v20Decision("A3T"));

        assertThat(attack.juxtaposition().coreAdverseLabels()).extracting(CoreAdverseLabels.Reading::label,
                CoreAdverseLabels.Reading::met).containsExactly(tuple("authorizationeffect", false),
                tuple("sessiondevicechange", false), tuple("sessionnetworkchange", false),
                tuple("dataconflicts", false), tuple("blockeduser", false), tuple("policysatisfied", true));
        assertThat(attack.juxtaposition().coreAdverseLabels().get(0).values()).containsExactly("ALLOW");
        assertThat(attack.juxtaposition().coreAdverseLabels().get(5).values()).singleElement()
                .satisfies(value -> assertThat(value).startsWith("no ").endsWith("no approval for GB-500"));
        assertThat(attack.juxtaposition().adverseMet()).isEqualTo(1L);
        assertThat(attack.juxtaposition().adverseChecked()).isEqualTo(6);
        assertThat(BeforeSend.companyAdverse(attack.juxtaposition().coreAdverseLabels()))
                .extracting(CoreAdverseLabels.Reading::label).containsExactly("policysatisfied");
        assertThat(owner.juxtaposition().coreAdverseLabels()).filteredOn(reading -> reading.label()
                .equals("policysatisfied")).singleElement().satisfies(policy -> {
                    assertThat(policy.met()).isFalse();
                    assertThat(policy.values()).singleElement().satisfies(value -> assertThat(value)
                            .startsWith("yes ").contains("approval APR-f2855b9824ce-1"));
                });
        assertThat(BeforeSend.companyAdverse(owner.juxtaposition().coreAdverseLabels())).isEmpty();
    }

    /** Step 1 of a case of anatomy/v20-deviations.json, built as the store builds it; no model call is kept. */
    private DecisionAnatomy v20(JsonNode decision) throws IOException {
        return fromMetadata(JSON.readTree(decision.path("records").get(0).path("metadataJson").asText()),
                decision.path("userPrompt").asText());
    }

    private DecisionAnatomy fromMetadata(JsonNode metadata, String userPrompt) {
        ArrayNode records = JSON.createArrayNode();
        records.addObject().put("metadataJson", metadata.toString());
        StoredDecision stored = new StoredDecision("request-v20", "ESCALATE", "ESCALATE", null, null, null, null,
                false, null, null, null, null, null, records, JSON.createArrayNode());
        return builder.build("run-v20", 1, "EXPORT_STREAM", stored, List.of(), null,
                new Surroundings(null, null, null, Map.of(), Map.of(), null, null, userPrompt));
    }

    private static JsonNode v20Decision(String caseKey) throws IOException {
        for (JsonNode decision : sample("v20-deviations").path("decisions")) {
            if (caseKey.equals(decision.path("case").asText())) {
                return decision;
            }
        }
        throw new IllegalArgumentException("no " + caseKey + " in anatomy/v20-deviations.json");
    }

    private DecisionAnatomy build(JsonNode sample) {
        return build(sample, Map.of(), Map.of(), null);
    }

    private DecisionAnatomy build(JsonNode sample, Map<String, Object> template, Map<String, Object> learning,
                                  Map<String, Object> challenge) {
        JsonNode decision = sample.path("decision");
        List<StoredCall> calls = new ArrayList<>();
        String systemPrompt = null;
        String userPrompt = null;
        for (JsonNode exchange : sample.path("exchanges")) {
            calls.add(new StoredCall(exchange.path("callNo").asInt(), text(exchange, "model"),
                    exchange.hasNonNull("requestOptions") ? exchange.get("requestOptions").toString() : null,
                    text(exchange, "finishReason"), longOrNull(exchange, "promptTokens"),
                    longOrNull(exchange, "completionTokens"), longOrNull(exchange, "reasoningTokens"),
                    longOrNull(exchange, "elapsedMs"), exchange.path("success").asBoolean(),
                    text(exchange, "failure"), exchange.hasNonNull("httpStatus") ? exchange.get("httpStatus").asInt() : null,
                    text(exchange, "answer"), exchange.path("maskedSessionIds").asInt(),
                    Instant.parse(text(exchange, "finishedAt")), "sha-of-the-sample-system-prompt"));
            systemPrompt = text(exchange, "systemPrompt");
            userPrompt = text(exchange, "userPrompt");
        }
        StoredDecision stored = new StoredDecision(text(decision, "request_id"), text(decision, "final_action"),
                text(decision, "proposed_action"), doubleOrNull(decision, "risk_score"),
                doubleOrNull(decision, "confidence"), text(decision, "reasoning"), text(decision, "mitre"),
                decision.path("unresolved").asBoolean(), text(decision, "failure_type"),
                text(decision, "fallback_category"), text(decision, "applied"), longOrNull(decision, "llm_latency_ms"),
                longOrNull(decision, "total_analysis_ms"), decision.get("records"), decision.get("events"));
        int stepNo = decision.path("step_no").asInt();
        JsonNode oracle = sample.path("scenarioDefinition").path("oracle");
        List<String> allowed = new ArrayList<>();
        oracle.path("allowedEngineActions").forEach(action -> allowed.add(action.asText()));
        Scoring.Truth truth = new Scoring.Truth(oracle.path("classification").asText(), allowed);
        Scoring.VerdictScore verdict = Scoring.verdicts(truth, List.of(new Scoring.StepDecision(stepNo,
                stored.finalAction(), stored.unresolved(), stored.applied())), stepNo).get(0);
        StepVerdict stepVerdict = new StepVerdict(verdict,
                stored.unresolved() ? DecisionSource.FALLBACK : DecisionSource.MODEL, stored.proposedAction());
        RunScore score = new RunScore(text(decision, "run_id"), sample.path("scenarioDefinition").path("key").asText(),
                sample.path("scenarioDefinition").path("version").asInt(), "COMPLETED", TruthSource.RUN_SNAPSHOT,
                truth, sample.path("scenarioDefinition").path("steps").size(), stepNo, Map.of(), Map.of(),
                List.of(stepVerdict), List.of(), null);
        return builder.build(text(decision, "run_id"), stepNo, "EXPORT_STREAM", stored, calls, systemPrompt,
                new Surroundings(score, sample.get("scenarioDefinition"), "sha-of-the-sample-definition", template,
                        learning, challenge, null, userPrompt));
    }

    private static JsonNode sample(String name) throws IOException {
        try (InputStream in = AnatomyBuilderTest.class.getResourceAsStream("/anatomy/" + name + ".json")) {
            return JSON.readTree(in);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static Long longOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asLong();
    }

    private static Double doubleOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asDouble();
    }
}
