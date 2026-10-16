package io.contexa.showcase.portal.reactivity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.benchmark.BenchmarkService;
import io.contexa.showcase.portal.benchmark.BenchmarkView;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * W6-1 (P6-CHANGE-2, plan 8.4 to 8.7): the harness metrics, each step's sealed prompt read from control D. Delivery,
 * reaction and injection read the runs of one harness batch (table reactivity_run); invariance reads the repetitions
 * of a measurement.
 */
public class ReactivityService {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final WorkloadAdmin admin;
    private final NamedParameterJdbcTemplate jdbc;
    private final DeliveryEvaluator evaluator;
    private final ReactionEvaluator reaction;
    private final InjectionEvaluator injection;
    private final ReactivityRuns runs;

    public ReactivityService(WorkloadAdmin admin, NamedParameterJdbcTemplate jdbc, DeliveryEvaluator evaluator,
                             ReactionEvaluator reaction, InjectionEvaluator injection, ReactivityRuns runs) {
        this.admin = admin;
        this.jdbc = jdbc;
        this.evaluator = evaluator;
        this.reaction = reaction;
        this.injection = injection;
        this.runs = runs;
    }

    /** One step compared: its request IDs and the delivery, or why it could not be compared. */
    public record StepDelivery(int stepNo, String baseRequestId, String variantRequestId,
                               DeliveryEvaluator.Delivery delivery, String notCompared) {
    }

    /** The two runs compared under a condition: every step, and whether every compared step was delivered. */
    public record RunDelivery(String baseRunId, String variantRunId, String condition, String value,
                              List<StepDelivery> steps, boolean passed) {
    }

    /** The lab runs of a batch against the batch's designed run of the same case, by condition. */
    public record BatchDelivery(BenchmarkView.Rate delivered, Map<String, BenchmarkView.Rate> byCondition,
                                int withoutBase, List<RunDelivery> runs) {
    }

    /** The four metrics; a part is null when its source was not asked for. */
    public record Report(String batchId, String protocolId, BatchDelivery delivery, ReactionEvaluator.Summary reaction,
                         InvarianceEvaluator.Invariance invariance, InjectionEvaluator.Summary injection) {
    }

    /** One decision row of a run step: request, final action and the records the engine reported. */
    private record Decision(int stepNo, String requestId, String finalAction, String records) {
    }

    public RunDelivery delivery(String baseRunId, String variantRunId, String condition) throws IOException {
        return delivery(baseRunId, variantRunId, condition, null);
    }

    public RunDelivery delivery(String baseRunId, String variantRunId, String condition, String value)
            throws IOException {
        Map<Integer, String> base = requests(baseRunId);
        Map<Integer, String> variant = requests(variantRunId);
        List<StepDelivery> steps = new ArrayList<>();
        for (Map.Entry<Integer, String> step : base.entrySet()) {
            String variantRequest = variant.get(step.getKey());
            if (variantRequest == null) {
                steps.add(new StepDelivery(step.getKey(), step.getValue(), null, null, "NO_VARIANT_STEP"));
                continue;
            }
            Optional<JsonNode> baseFacts = admin.promptFacts(step.getValue());
            Optional<JsonNode> variantFacts = admin.promptFacts(variantRequest);
            if (baseFacts.isEmpty() || variantFacts.isEmpty()) {
                steps.add(new StepDelivery(step.getKey(), step.getValue(), variantRequest, null, "NOT_SEALED"));
                continue;
            }
            steps.add(new StepDelivery(step.getKey(), step.getValue(), variantRequest,
                    evaluator.compare(PromptFacts.of(baseFacts.get()), PromptFacts.of(variantFacts.get()), condition,
                            value),
                    null));
        }
        boolean passed = !steps.isEmpty() && steps.stream().allMatch(step -> step.delivery() != null
                && step.delivery().passed());
        return new RunDelivery(baseRunId, variantRunId, condition, value, List.copyOf(steps), passed);
    }

    /** The metrics of a harness batch and of a measurement's repetitions; either may be null. */
    public Report report(String batchId, String protocolId) throws IOException {
        BatchDelivery delivery = null;
        ReactionEvaluator.Summary reacted = null;
        InjectionEvaluator.Summary injected = null;
        if (batchId != null) {
            List<ReactivityRuns.Entry> entries = runs.batch(batchId);
            delivery = batchDelivery(entries);
            reacted = batchReaction(entries);
            injected = batchInjection(entries);
        }
        return new Report(batchId, protocolId, delivery, reacted, protocolId != null ? invariance(protocolId) : null,
                injected);
    }

    private BatchDelivery batchDelivery(List<ReactivityRuns.Entry> entries) throws IOException {
        List<RunDelivery> compared = new ArrayList<>();
        int withoutBase = 0;
        for (ReactivityRuns.Entry entry : entries) {
            if (entry.kind() != ReactivityRuns.Kind.LAB) {
                continue;
            }
            String[] condition = conditionOf(entry.label());
            Optional<ReactivityRuns.Entry> base = baseOf(entries, entry.caseKey(), 0);
            if (condition == null || base.isEmpty()) {
                withoutBase++;
                continue;
            }
            compared.add(delivery(base.get().runId(), entry.runId(), condition[0], condition[1]));
        }
        Map<String, long[]> counts = new LinkedHashMap<>();
        for (RunDelivery run : compared) {
            long[] cell = counts.computeIfAbsent(run.condition(), key -> new long[2]);
            cell[1]++;
            if (run.passed()) {
                cell[0]++;
            }
        }
        Map<String, BenchmarkView.Rate> byCondition = new LinkedHashMap<>();
        counts.forEach((name, cell) -> byCondition.put(name, BenchmarkService.rate(cell[0], cell[1])));
        long delivered = compared.stream().filter(RunDelivery::passed).count();
        return new BatchDelivery(BenchmarkService.rate(delivered, compared.size()), byCondition, withoutBase,
                List.copyOf(compared));
    }

    private ReactionEvaluator.Summary batchReaction(List<ReactivityRuns.Entry> entries) throws IOException {
        List<ReactionEvaluator.RunReaction> judged = new ArrayList<>();
        int notInMatrix = 0;
        for (ReactivityRuns.Entry entry : entries) {
            if (entry.kind() != ReactivityRuns.Kind.LAB && entry.kind() != ReactivityRuns.Kind.VARIANT) {
                continue;
            }
            if (reaction.variant(entry.label()).isEmpty()) {
                notInMatrix++;
                continue;
            }
            List<ReactionEvaluator.Step> steps = new ArrayList<>();
            for (Decision decision : decisions(entry.runId())) {
                Optional<JsonNode> facts = admin.promptFacts(decision.requestId());
                steps.add(new ReactionEvaluator.Step(decision.stepNo(), decision.finalAction(),
                        findings(decision.records()), facts.map(PromptFacts::of).orElse(null)));
            }
            judged.add(reaction.judge(entry.runId(), entry.label(), steps));
        }
        return reaction.summarise(judged, notInMatrix);
    }

    private InjectionEvaluator.Summary batchInjection(List<ReactivityRuns.Entry> entries) throws IOException {
        List<InjectionEvaluator.RunInjection> judged = new ArrayList<>();
        int withoutBase = 0;
        Map<String, Integer> repetition = new HashMap<>();
        for (ReactivityRuns.Entry entry : entries) {
            if (entry.kind() != ReactivityRuns.Kind.INJECTION) {
                continue;
            }
            Optional<InjectionEvaluator.Place> place = injection.place(entry.label());
            int index = repetition.merge(entry.label(), 1, Integer::sum) - 1;
            Optional<ReactivityRuns.Entry> base = place.flatMap(found -> baseOf(entries, found.base(), index));
            if (base.isEmpty()) {
                withoutBase++;
                continue;
            }
            judged.add(injection.judge(entry.runId(), entry.label(), injectionSteps(entry.runId()),
                    base.get().runId(), injectionSteps(base.get().runId())));
        }
        return injection.summarise(judged, withoutBase);
    }

    private InvarianceEvaluator.Invariance invariance(String protocolId) throws IOException {
        Map<String, List<InvarianceEvaluator.Run>> repetitions = new LinkedHashMap<>();
        List<Map<String, Object>> rows = jdbc.queryForList("select run_id, scenario_key, coalesce(template_id, '') "
                        + "template_id from run where protocol_id = :protocol and forced_action is null "
                        + "order by started_at, run_id",
                new MapSqlParameterSource("protocol", protocolId));
        for (Map<String, Object> row : rows) {
            String runId = (String) row.get("run_id");
            List<InvarianceEvaluator.Step> steps = new ArrayList<>();
            for (Decision decision : decisions(runId)) {
                Optional<JsonNode> facts = admin.promptFacts(decision.requestId());
                steps.add(new InvarianceEvaluator.Step(decision.stepNo(), decision.requestId(), decision.finalAction(),
                        facts.map(PromptFacts::of).orElse(null)));
            }
            // Repetitions of one measurement with one template: another template is another baseline.
            String repeated = row.get("scenario_key") + "|" + row.get("template_id");
            repetitions.computeIfAbsent(repeated, key -> new ArrayList<>())
                    .add(new InvarianceEvaluator.Run(runId, List.copyOf(steps)));
        }
        return new InvarianceEvaluator(evaluator).evaluate(repetitions);
    }

    /** The designed run of a case in a batch: the index-th, or the first when there are fewer. */
    private static Optional<ReactivityRuns.Entry> baseOf(List<ReactivityRuns.Entry> entries, String caseKey,
                                                         int index) {
        List<ReactivityRuns.Entry> bases = entries.stream()
                .filter(entry -> entry.kind() == ReactivityRuns.Kind.BASE && entry.caseKey().equals(caseKey))
                .toList();
        if (bases.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(bases.get(index < bases.size() ? index : 0));
    }

    /** "A3:timeSlot=AFTERNOON" gives the condition and the value; null when the label names no condition. */
    static String[] conditionOf(String label) {
        int colon = label.indexOf(':');
        int equals = label.indexOf('=', colon + 1);
        if (colon < 0 || equals < 0) {
            return null;
        }
        return new String[] {label.substring(colon + 1, equals), label.substring(equals + 1)};
    }

    private List<InjectionEvaluator.Step> injectionSteps(String runId) throws IOException {
        List<InjectionEvaluator.Step> steps = new ArrayList<>();
        for (Decision decision : decisions(runId)) {
            List<InjectionEvaluator.Line> lines = new ArrayList<>();
            Optional<JsonNode> facts = admin.promptFacts(decision.requestId());
            if (facts.isPresent()) {
                for (JsonNode line : facts.get().path("lines")) {
                    lines.add(new InjectionEvaluator.Line(line.path("block").asText(null),
                            line.path("label").asText(""), line.path("value").asText("")));
                }
            }
            steps.add(new InjectionEvaluator.Step(decision.stepNo(), decision.finalAction(), List.copyOf(lines)));
        }
        return steps;
    }

    /** The minimum-action findings the engine kept in a decision's records (metadataJson minimumActionFindings). */
    static List<ReactionEvaluator.Finding> findings(String records) throws IOException {
        List<ReactionEvaluator.Finding> findings = new ArrayList<>();
        if (records == null) {
            return findings;
        }
        for (JsonNode record : JSON.readTree(records)) {
            JsonNode metadata = record.path("metadataJson");
            if (metadata.isTextual()) {
                metadata = metadata.asText().isBlank() ? JSON.createObjectNode() : JSON.readTree(metadata.asText());
            }
            for (JsonNode finding : metadata.path("minimumActionFindings")) {
                findings.add(new ReactionEvaluator.Finding(finding.path("rule").asText(),
                        finding.path("requiredAction").asText(null), finding.path("decidedAction").asText(null),
                        finding.path("violated").asBoolean(false)));
            }
        }
        return findings;
    }

    private List<Decision> decisions(String runId) {
        Map<Integer, Decision> decisions = new LinkedHashMap<>();
        jdbc.query("select step_no, request_id::text, final_action, records::text from run_decision "
                        + "where run_id = :run order by step_no, decided_at",
                new MapSqlParameterSource("run", runId),
                rs -> {
                    decisions.putIfAbsent(rs.getInt(1), new Decision(rs.getInt(1), rs.getString(2), rs.getString(3),
                            rs.getString(4)));
                });
        return List.copyOf(decisions.values());
    }

    private Map<Integer, String> requests(String runId) {
        Map<Integer, String> requests = new LinkedHashMap<>();
        decisions(runId).forEach(decision -> requests.put(decision.stepNo(), decision.requestId()));
        return requests;
    }
}
