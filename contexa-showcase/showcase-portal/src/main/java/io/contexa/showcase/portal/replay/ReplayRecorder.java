package io.contexa.showcase.portal.replay;

import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.replay.PairDefinition.Scene;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * Recording harness (plan P2 step 2): every scene of a pair runs n times, each on a fresh principal through the
 * orchestrator, and is stored as a draft with "k of n agree" (plan 1절). All runs of a scene must share one execution
 * specification; a scene whose runs did not complete or ran under different specifications is not stored.
 */
public class ReplayRecorder {

    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC);

    public record SceneResult(String pairKey, String scene, String recordId, int agreeing, int repetitions,
                              String specHash, String failure) {
    }

    private final PairCatalog pairs;
    private final ScenarioCatalog scenarios;
    private final RunOrchestrator orchestrator;
    private final ReplayStore store;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public ReplayRecorder(PairCatalog pairs, ScenarioCatalog scenarios, RunOrchestrator orchestrator, ReplayStore store,
                          Clock clock) {
        this.pairs = pairs;
        this.scenarios = scenarios;
        this.orchestrator = orchestrator;
        this.store = store;
        this.clock = clock;
    }

    public List<SceneResult> record(String pairKey, int repetitions) throws IOException {
        PairDefinition pair = pairs.find(pairKey)
                .orElseThrow(() -> new IllegalArgumentException("Unknown pair " + pairKey));
        if (repetitions < 1) {
            throw new IllegalArgumentException("repetitions must be positive");
        }
        if (orchestrator.engineAcceptsForcedDecisions()) {
            throw new IllegalStateException("Replays are not recorded while control D accepts forced decisions");
        }
        List<SceneResult> results = new ArrayList<>();
        for (Scene scene : pair.scenes()) {
            results.add(recordScene(pair, scene, repetitions));
        }
        return results;
    }

    private SceneResult recordScene(PairDefinition pair, Scene scene, int repetitions) throws IOException {
        ScenarioDefinition scenario = scenarios.find(scene.scenario()).orElseThrow();
        List<RunSummary> runs = new ArrayList<>();
        for (int i = 0; i < repetitions; i++) {
            runs.add(orchestrator.run(scenario));
        }
        List<String> specs = new ArrayList<>();
        for (RunSummary run : runs) {
            if (!"COMPLETED".equals(run.status())) {
                return failed(pair, scene, repetitions, "run " + run.runId() + " " + run.status() + ": "
                        + run.failure());
            }
            specs.add(store.specHashOf(run.runId()).orElse(null));
        }
        if (specs.stream().anyMatch(Objects::isNull) || specs.stream().distinct().count() != 1) {
            return failed(pair, scene, repetitions, "runs have no or different execution specifications: " + specs);
        }
        List<String> signatures = runs.stream().map(OutcomeSignature::of).toList();
        OutcomeSignature.Mode mode = OutcomeSignature.mode(signatures);
        String representative = runs.get(signatures.indexOf(mode.signature())).runId();
        String recordId = "rec-" + pair.key().toLowerCase() + "-" + scene.kind().name().toLowerCase().charAt(0) + "-"
                + STAMP.format(clock.instant()) + "-" + HexFormat.of().formatHex(bytes());
        List<ReplayStore.RecordedRun> recorded = new ArrayList<>();
        for (int i = 0; i < runs.size(); i++) {
            recorded.add(new ReplayStore.RecordedRun(runs.get(i).runId(), i + 1, signatures.get(i)));
        }
        store.save(new ReplayStore.RecordRow(recordId, pair.key(), scene.kind(), scenario.key(), scenario.version(),
                specs.get(0), repetitions, mode.agreeing(), representative, mode.signature(), "DRAFT", null, null),
                recorded);
        return new SceneResult(pair.key(), scene.kind().name(), recordId, mode.agreeing(), repetitions, specs.get(0),
                null);
    }

    private static SceneResult failed(PairDefinition pair, Scene scene, int repetitions, String failure) {
        return new SceneResult(pair.key(), scene.kind().name(), null, 0, repetitions, null, failure);
    }

    private byte[] bytes() {
        byte[] bytes = new byte[3];
        random.nextBytes(bytes);
        return bytes;
    }
}
