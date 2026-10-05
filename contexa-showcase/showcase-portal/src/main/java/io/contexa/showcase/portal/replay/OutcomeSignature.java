package io.contexa.showcase.portal.replay;

import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.StepSummary;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The comparable result of one run: per step, the business outcome of every control in layer order and the engine's
 * decision with its resolution. Two repetitions agree when their signatures are equal ("k of 5 agree", plan 1절).
 * Identities, times and wording are left out on purpose; they always differ between fresh principals.
 */
public final class OutcomeSignature {

    public static final List<String> CONTROLS = List.of("A", "B", "C1", "C2", "D");

    private OutcomeSignature() {
    }

    public static String of(RunSummary run) {
        List<String> steps = new ArrayList<>();
        for (StepSummary step : run.steps()) {
            StringBuilder text = new StringBuilder().append(step.stepNo()).append(':');
            for (String control : CONTROLS) {
                text.append(control).append('=').append(Objects.toString(step.outcomes().get(control), "-"))
                        .append(',');
            }
            text.append("engine=").append(Objects.toString(step.engineAction(), "-"))
                    .append(",unresolved=").append(step.unresolved());
            steps.add(text.toString());
        }
        return run.status() + "|" + String.join("|", steps);
    }

    /** The most frequent signature (the earliest one on a tie) and how many signatures equal it. */
    public static Mode mode(List<String> signatures) {
        if (signatures.isEmpty()) {
            throw new IllegalArgumentException("No signatures");
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        signatures.forEach(signature -> counts.merge(signature, 1, Integer::sum));
        String best = null;
        int bestCount = 0;
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            if (entry.getValue() > bestCount) {
                best = entry.getKey();
                bestCount = entry.getValue();
            }
        }
        return new Mode(best, bestCount, signatures.size());
    }

    public record Mode(String signature, int agreeing, int repetitions) {
    }
}
