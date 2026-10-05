package io.contexa.showcase.portal.replay;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.replay.PairDefinition.SceneKind;
import io.contexa.showcase.portal.replay.ReplayStore.ArmRow;
import io.contexa.showcase.portal.replay.ReplayStore.DecisionRow;
import io.contexa.showcase.portal.replay.ReplayStore.RecordRow;
import io.contexa.showcase.portal.replay.ReplayView.EngineReason;
import io.contexa.showcase.portal.replay.ReplayView.Evidence;
import io.contexa.showcase.portal.replay.ReplayView.Fact;
import io.contexa.showcase.portal.replay.ReplayView.Layer;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Builds the visitor view of a recorded pair from the stored rows of each scene's representative run. Business outcome
 * comes from the control's actual response; a 403 counts as the engine's block only when it carries an engine
 * decision (deck p.24), and an unresolved engine decision is shown as pending, never as a verdict.
 */
public class ReplayViews {

    private static final TypeReference<Map<String, Object>> FACTS = new TypeReference<>() {
    };

    /** Fixed sentences of the engine's output contract (core prompt reasoning rules), by code. */
    static final Map<String, String> CANONICAL_REASONS = Map.of(
            "A trusted internal security signal confirmed malicious activity; final autonomous action is BLOCK.",
            "TRUSTED_SIGNAL_BLOCK",
            "Repeated failed logins and abusive request volume combine with device mismatch and bot or transport "
                    + "tampering; final autonomous action is BLOCK.", "CORROBORATED_ATTACK_BLOCK",
            "Authorization allows access, the personal baseline is established, and no concrete risk or verification "
                    + "requirement is present.", "ALLOW_BASELINE_NO_RISK",
            "Authorization allows access with a limited baseline, and no concrete risk or verification requirement is "
                    + "present.", "ALLOW_LIMITED_BASELINE_NO_RISK",
            "Authorization allows access, the personal baseline is established, and authorized RAG is relevant to the "
                    + "same resource.", "ALLOW_BASELINE_SAME_RESOURCE_HISTORY",
            "Authorization allows access, and authorized RAG is relevant to the same resource.",
            "ALLOW_SAME_RESOURCE_HISTORY",
            "Fresh verification is required before allowing access; challenge is safer than allow.",
            "CHALLENGE_FRESH_VERIFICATION");

    private final PairCatalog pairs;
    private final ReplayStore store;
    private final ObjectMapper json;

    public ReplayViews(PairCatalog pairs, ReplayStore store, ObjectMapper json) {
        this.pairs = pairs;
        this.store = store;
        this.json = json;
    }

    public List<ReplayView.PairSummary> summaries() {
        return pairs.all().stream().map(pair -> new ReplayView.PairSummary(pair.key(), pair.order(), pair.question(),
                Arrays.stream(SceneKind.values()).allMatch(kind -> store.published(pair.key(), kind).isPresent())))
                .toList();
    }

    /** The published pair, present only when both scenes have a published record. */
    public Optional<ReplayView.Pair> published(String pairKey) {
        Optional<PairDefinition> pair = pairs.find(pairKey);
        if (pair.isEmpty()) {
            return Optional.empty();
        }
        List<ReplayView.Scene> scenes = new ArrayList<>();
        for (PairDefinition.Scene scene : pair.get().scenes()) {
            Optional<RecordRow> record = store.published(pairKey, scene.kind());
            if (record.isEmpty()) {
                return Optional.empty();
            }
            scenes.add(scene(scene, record.get()));
        }
        return Optional.of(new ReplayView.Pair(pair.get().key(), pair.get().question(), scenes));
    }

    /** One record as the visitor would see it, for the operator's review before publishing. */
    public Optional<ReplayView.Scene> preview(String recordId) {
        return store.find(recordId).flatMap(record -> pairs.find(record.pairKey())
                .map(pair -> scene(pair.scene(record.scene()), record)));
    }

    ReplayView.Scene scene(PairDefinition.Scene scene, RecordRow record) {
        String runId = record.representativeRunId();
        int step = scene.featuredStep();
        ReplayView.StepResult result = step(runId, step);
        return new ReplayView.Scene(scene.kind().name(), scene.sentence(), record.recordId(), record.agreeing(),
                record.repetitions(), record.recordedAt(), record.specHash(), result.companyTime(), step,
                store.stepCount(runId), result.layers(), result.engineReason(), result.companyFacts());
    }

    /** One step of a stored run as the visitor sees it: replays and combination records share this view. */
    public ReplayView.StepResult step(String runId, int step) {
        Map<String, ArmRow> arms = store.arms(runId, step);
        Optional<DecisionRow> decision = store.decision(runId, step);
        Map<String, JsonNode> ruleDecisions = store.ruleDecisions(runId);
        List<Layer> layers = new ArrayList<>();
        for (String control : OutcomeSignature.CONTROLS) {
            ArmRow arm = arms.get(control);
            if (arm == null) {
                throw new IllegalStateException("Run " + runId + " step " + step + " has no result of " + control);
            }
            layers.add("D".equals(control) ? engineLayer(arm, decision)
                    : ruleLayer(arm, ruleDecisions.get(arm.requestId()), json));
        }
        ArmRow context = arms.get("C2");
        return new ReplayView.StepResult(arms.get("D").companyTime(), layers, engineReason(decision),
                companyFacts(ruleDecisions.get(context.requestId())));
    }

    /**
     * A rule control's layer. Its own decision record of the request gives the rule and the facts it looked at; a
     * refusal without such a record came from in front of the control (the WAF of control A).
     */
    static Layer ruleLayer(ArmRow arm, JsonNode ruleDecision, ObjectMapper json) {
        String outcome = outcome(arm, false);
        String verdict = "DELIVERED".equals(outcome) ? "ALLOW" : "UNRESOLVED".equals(outcome) ? "PENDING" : "BLOCK";
        String ruleId = arm.ruleId();
        String reason = arm.reason();
        Map<String, Object> facts = Map.of();
        if (ruleDecision != null) {
            ruleId = ruleDecision.path("rule_id").asText(ruleId);
            reason = ruleDecision.path("reason").asText(reason);
            facts = facts(ruleDecision.path("facts").asText("{}"), json);
        }
        return new Layer(arm.control(), outcome, verdict, arm.httpStatus(), ruleId, reason, facts,
                new Evidence(arm.requestId(), verdict, "BEFORE_RESPONSE", arm.httpStatus(), outcome,
                        arm.deliveredItems(), null, null, null, false, arm.elapsedMs(), List.of(), stream(arm)));
    }

    private static Map<String, Object> facts(String text, ObjectMapper json) {
        try {
            return json.readValue(text, FACTS);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable rule decision facts", e);
        }
    }

    static Layer engineLayer(ArmRow arm, Optional<DecisionRow> decision) {
        boolean engineHeld = arm.httpStatus() != null && (arm.httpStatus() == 401 || arm.httpStatus() == 423);
        String outcome = outcome(arm, engineHeld);
        if (decision.isEmpty() || decision.get().finalAction() == null) {
            boolean refused = !"DELIVERED".equals(outcome);
            String verdict = refused ? "BLOCK" : "ALLOW";
            String timing = refused ? "STATIC_AUTHORIZATION" : "NOT_ANALYSED";
            return new Layer(arm.control(), outcome, verdict, arm.httpStatus(), arm.ruleId(), arm.reason(), Map.of(),
                    new Evidence(null, verdict, timing, arm.httpStatus(), outcome, arm.deliveredItems(), null, null,
                            null, false, arm.elapsedMs(), List.of(), stream(arm)));
        }
        DecisionRow engine = decision.get();
        String verdict = engine.unresolved() ? "PENDING" : engine.finalAction();
        String timing = "CUT".equals(outcome) ? "MID_RESPONSE" : engine.applied();
        return new Layer(arm.control(), outcome, verdict, arm.httpStatus(), null, null, Map.of(),
                new Evidence(engine.requestId(), verdict, timing, arm.httpStatus(), outcome,
                        arm.deliveredItems(), engine.reasoning(), engine.riskScore(), engine.confidence(),
                        engine.unresolved(), arm.elapsedMs(), timeline(arm.sentAt(), engine.events()), stream(arm)));
    }

    /** The stored progress of a streamed export, or null for other operations. */
    static ReplayView.Stream stream(ArmRow arm) {
        JsonNode stream = arm.stream();
        if (stream == null || !stream.isObject()) {
            return null;
        }
        List<long[]> samples = new ArrayList<>();
        stream.path("samples").forEach(sample -> samples.add(new long[]{sample.path(0).asLong(),
                sample.path(1).asLong()}));
        return new ReplayView.Stream(stream.hasNonNull("total") ? stream.path("total").asInt() : null,
                stream.path("delivered").asInt(), stream.hasNonNull("firstLineMs")
                ? stream.path("firstLineMs").asLong() : null, stream.path("endMs").asLong(),
                stream.hasNonNull("cut"), stream.path("interrupted").asBoolean(), samples);
    }

    /** Engine events timed from the moment the request was sent; events without a time are left out. */
    static List<ReplayView.TimelineEvent> timeline(Instant sentAt, JsonNode events) {
        List<ReplayView.TimelineEvent> timeline = new ArrayList<>();
        if (sentAt == null || events == null || !events.isArray()) {
            return timeline;
        }
        for (JsonNode event : events) {
            String observedAt = event.path("observedAt").asText(null);
            if (observedAt == null) {
                continue;
            }
            long atMs = Duration.between(sentAt, Instant.parse(observedAt)).toMillis();
            timeline.add(new ReplayView.TimelineEvent(event.path("type").asText(), event.path("layer").asText(null),
                    event.path("action").asText(null), atMs,
                    event.hasNonNull("elapsedMs") ? event.path("elapsedMs").asLong() : null));
        }
        return timeline;
    }

    static String outcome(ArmRow arm, boolean held) {
        return switch (arm.outcome()) {
            case "DELIVERED" -> "DELIVERED";
            case "ERROR" -> "UNRESOLVED";
            case "CUT" -> "CUT";
            default -> held ? "HELD" : "STOPPED";
        };
    }

    EngineReason engineReason(Optional<DecisionRow> decision) {
        if (decision.isEmpty() || decision.get().finalAction() == null) {
            return null;
        }
        DecisionRow engine = decision.get();
        JsonNode metadata = metadata(engine.records());
        List<String> refs = new ArrayList<>();
        metadata.path("evidenceRefs").forEach(ref -> refs.add(ref.asText()));
        List<String> deltas = new ArrayList<>();
        String combination = metadata.path("strongestCurrentRequestCombinationDelta").asText("");
        int differing = combination.indexOf("differing=");
        if (differing >= 0) {
            for (String dimension : combination.substring(differing + "differing=".length()).split(",")) {
                if (!dimension.isBlank()) {
                    deltas.add(dimension.trim());
                }
            }
        }
        String reasoning = engine.reasoning();
        return new EngineReason(reasoning == null ? null : CANONICAL_REASONS.get(reasoning.trim()), reasoning, refs,
                deltas, metadata.path("resourceSensitivity").asText(null));
    }

    private JsonNode metadata(JsonNode records) {
        if (records == null || !records.isArray() || records.isEmpty()) {
            return json.createObjectNode();
        }
        String text = records.get(0).path("metadataJson").asText(null);
        if (text == null) {
            return json.createObjectNode();
        }
        try {
            return json.readTree(text);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable engine decision metadata", e);
        }
    }

    /** The facts the shared business lookup returned for the context rule control's copy of the request. */
    List<Fact> companyFacts(JsonNode ruleDecision) {
        List<Fact> facts = new ArrayList<>();
        if (ruleDecision == null) {
            return facts;
        }
        JsonNode values;
        try {
            values = json.readTree(ruleDecision.path("facts").asText("{}"));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable rule decision facts", e);
        }
        if (values.has("assigned")) {
            facts.add(new Fact(values.path("assigned").path("assigned").asBoolean() ? "ASSIGNED" : "NOT_ASSIGNED",
                    values.path("projectKey").asText(null)));
        }
        if (values.has("approval")) {
            JsonNode approval = values.path("approval");
            facts.add(new Fact(approval.path("covered").asBoolean() ? "APPROVAL_COVERS" : "NO_APPROVAL",
                    approval.path("purpose").asText(null)));
        }
        if (values.has("ticket")) {
            JsonNode ticket = values.path("ticket");
            facts.add(new Fact(ticket.path("covered").asBoolean() ? "TICKET_COVERS" : "NO_TICKET",
                    ticket.path("ticketKey").asText(null)));
        }
        if (values.has("oncall")) {
            facts.add(new Fact(values.path("oncall").path("onCall").asBoolean() ? "ON_CALL" : "NOT_ON_CALL", null));
        }
        if (values.has("accessDaysLast30")) {
            facts.add(new Fact("ACCESS_DAYS_LAST_30", values.path("accessDaysLast30").asText()));
        }
        if (values.has("items")) {
            facts.add(new Fact("ITEMS", values.path("items").asText()));
        }
        if (values.has("network")) {
            JsonNode network = values.path("network");
            String kind = network.path("kind").asText("UNKNOWN");
            facts.add(new Fact("NETWORK_" + kind, "TRAVEL".equals(kind) ? network.path("city").asText(null) : null));
        }
        if (values.has("claim")) {
            JsonNode claim = values.path("claim");
            boolean confirmed = claim.path("exists").asBoolean() && claim.path("coverage").path("covered").asBoolean();
            facts.add(new Fact(confirmed ? "CLAIM_CONFIRMED" : "CLAIM_NOT_CONFIRMED", claim.path("ticketKey").asText(null)));
        }
        return facts;
    }
}
