package io.contexa.showcase.portal.replay;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.portal.replay.ReplayStore.RecordRow;
import io.contexa.showcase.portal.replay.ReplayStore.RecordedRun;
import io.contexa.showcase.portal.spec.ExecutionSpec;
import io.contexa.showcase.portal.spec.ExecutionSpecHasher;
import io.contexa.showcase.portal.spec.ExecutionSpecStore;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Consistency of the recordings with what produced them (P2-BE-01): every required execution specification field is
 * present and the stored hash recomputes from the stored fields, every run of the record exists under the same
 * specification, the agreement count matches the runs, and, when the engine is reachable, the engine still holds the
 * original decision record of every analysed step of the representative run.
 */
public class ReplayConsistency {

    /** Looks up the engine's original decision record of a request; empty when the engine has none. */
    @FunctionalInterface
    public interface EngineRecords {
        Optional<JsonNode> find(String requestId) throws IOException;
    }

    public record Finding(String recordId, List<String> problems) {
        public boolean consistent() {
            return problems.isEmpty();
        }
    }

    private final ReplayStore store;
    private final ExecutionSpecStore specs;

    public ReplayConsistency(ReplayStore store, ExecutionSpecStore specs) {
        this.store = store;
        this.specs = specs;
    }

    public List<Finding> check(EngineRecords engine) throws IOException {
        List<Finding> findings = new ArrayList<>();
        for (RecordRow record : store.list()) {
            if (!"RETIRED".equals(record.status())) {
                findings.add(check(record, engine));
            }
        }
        return findings;
    }

    public Finding check(RecordRow record, EngineRecords engine) throws IOException {
        List<String> problems = new ArrayList<>();
        Optional<ExecutionSpec> spec = specs.find(record.specHash());
        if (spec.isEmpty()) {
            problems.add("execution specification " + record.specHash() + " is missing");
        } else {
            requireText(problems, "codeCommit", spec.get().codeCommit());
            requireText(problems, "engineVersion", spec.get().engineVersion());
            requireText(problems, "effectiveMode", spec.get().effectiveMode());
            requireText(problems, "chatModel", spec.get().chatModel());
            requireText(problems, "embeddingModel", spec.get().embeddingModel());
            requireText(problems, "promptHash", spec.get().promptHash());
            requireText(problems, "ruleVersion", spec.get().ruleVersion());
            requireText(problems, "timeZone", spec.get().timeZone());
            if (spec.get().endpointProtection().isEmpty()) {
                problems.add("endpointProtection is empty");
            }
            String recomputed = ExecutionSpecHasher.hash(spec.get());
            if (!recomputed.equals(record.specHash())) {
                problems.add("specification hash recomputes to " + recomputed);
            }
        }
        List<RecordedRun> runs = store.runs(record.recordId());
        if (runs.size() != record.repetitions()) {
            problems.add(runs.size() + " runs stored for " + record.repetitions() + " repetitions");
        }
        long agreeing = runs.stream().filter(run -> run.outcomeSignature().equals(record.outcomeSignature())).count();
        if (agreeing != record.agreeing()) {
            problems.add(agreeing + " runs agree, the record says " + record.agreeing());
        }
        boolean representativeListed = false;
        for (RecordedRun run : runs) {
            representativeListed |= run.runId().equals(record.representativeRunId());
            Optional<String> runSpec = store.specHashOf(run.runId());
            if (runSpec.isEmpty() || !record.specHash().equals(runSpec.get())) {
                problems.add("run " + run.runId() + " has specification " + runSpec.orElse("none"));
            }
        }
        for (RecordedRun run : runs) {
            cutsBackedByEngineBlock(problems, run.runId());
            store.run(run.runId()).map(ReplayStore.RunRow::forcedAction).ifPresent(forced -> problems.add(
                    "run " + run.runId() + " used the development-only forced decision " + forced));
        }
        if (!representativeListed) {
            problems.add("representative run " + record.representativeRunId() + " is not one of the record's runs");
        }
        if (engine != null) {
            int steps = store.stepCount(record.representativeRunId());
            for (int step = 1; step <= steps; step++) {
                Optional<ReplayStore.DecisionRow> decision = store.decision(record.representativeRunId(), step);
                if (decision.isPresent() && decision.get().finalAction() != null
                        && engine.find(decision.get().requestId()).isEmpty()) {
                    problems.add("engine has no original decision record of step " + step + " ("
                            + decision.get().requestId() + ")");
                }
            }
        }
        return new Finding(record.recordId(), problems);
    }

    /**
     * P3-BE-02: a response is shown as cut only when control D cut it and the engine's decision of that very request is
     * BLOCK; any other cut would show a block that the engine did not decide.
     */
    private void cutsBackedByEngineBlock(List<String> problems, String runId) {
        int steps = store.stepCount(runId);
        for (int step = 1; step <= steps; step++) {
            for (ReplayStore.ArmRow arm : store.arms(runId, step).values()) {
                if (!"CUT".equals(arm.outcome())) {
                    continue;
                }
                Optional<ReplayStore.DecisionRow> decision = store.decision(runId, step);
                boolean blocked = decision.isPresent() && "BLOCK".equals(decision.get().finalAction())
                        && arm.requestId().equals(decision.get().requestId());
                if (!"D".equals(arm.control()) || !blocked) {
                    problems.add("run " + runId + " step " + step + " control " + arm.control()
                            + " is cut without an engine BLOCK of that request");
                }
            }
        }
    }

    private static void requireText(List<String> problems, String field, String value) {
        if (value == null || value.isBlank()) {
            problems.add(field + " is missing");
        }
    }
}
