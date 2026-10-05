package io.contexa.showcase.portal.combination;

import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import io.contexa.showcase.portal.replay.ReplayStore;
import io.contexa.showcase.portal.replay.ReplayView;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.spec.ScoringContract;
import io.contexa.showcase.portal.template.TemplateCurrency;
import io.contexa.showcase.portal.template.TemplateStore;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The exploration grid over stored real runs (deck p.13, docs/showcase/P4-설계.md 1절): a cell shows the first live run
 * of that combination under the current versions, with its time, or nothing yet. Nothing is filled in without a run.
 */
public class CombinationService {

    static final Duration VERSION_CACHE = Duration.ofSeconds(30);

    /** One cell of the map: the engine's verdict and business outcome of its stored run, or not run yet. */
    public record CellView(String key, TimeSlot slot, int items, boolean recorded, Instant recordedAt,
                           String engineVerdict, String engineOutcome) {
    }

    public record CombinationView(String key, String employee, TimeSlot slot, int items, Combination.Ticket ticket,
                                  Combination.Device device, boolean recorded, Instant recordedAt, String runId,
                                  ReplayView.StepResult result) {
    }

    private record CachedVersion(String key, Instant until) {
    }

    private final WorkloadAdmin admin;
    private final TemplateCurrency templates;
    private final ScoringContract contract;
    private final CombinationStore store;
    private final ReplayStore runs;
    private final ReplayViews views;
    private final Clock clock;
    private final Map<String, CachedVersion> versions = new HashMap<>();

    public CombinationService(WorkloadAdmin admin, TemplateCurrency templates, ScoringContract contract,
                              CombinationStore store, ReplayStore runs, ReplayViews views, Clock clock) {
        this.admin = admin;
        this.templates = templates;
        this.contract = contract;
        this.store = store;
        this.runs = runs;
        this.views = views;
        this.clock = clock;
    }

    /** The current version key of an employee's cells; read from control D at most every 30 seconds. */
    public synchronized String versionKey(String employee) throws IOException {
        CachedVersion cached = versions.get(employee);
        if (cached != null && clock.instant().isBefore(cached.until())) {
            return cached.key();
        }
        String templateId = templates.current(employee).map(TemplateStore.ReadyTemplate::templateId).orElse(null);
        String key = CombinationVersions.key(admin.engine(), admin.rules(), templateId, contract.version());
        versions.put(employee, new CachedVersion(key, clock.instant().plus(VERSION_CACHE)));
        return key;
    }

    /** The time-by-count map of one employee, ticket and device (deck p.13). */
    public List<CellView> grid(String employee, Combination.Ticket ticket, Combination.Device device)
            throws IOException {
        String versionKey = versionKey(employee);
        Map<String, CombinationStore.RecordRow> records = new HashMap<>();
        store.forVersions(List.of(versionKey)).forEach(record -> records.put(record.comboKey(), record));
        List<CellView> cells = new ArrayList<>();
        for (int items : Combination.ITEMS) {
            for (TimeSlot slot : TimeSlot.values()) {
                Combination combination = new Combination(employee, slot, items, ticket, device);
                CombinationStore.RecordRow record = records.get(combination.key());
                if (record == null) {
                    cells.add(new CellView(combination.key(), slot, items, false, null, null, null));
                } else {
                    ReplayView.Layer engine = engineLayer(views.step(record.runId(), 1));
                    cells.add(new CellView(combination.key(), slot, items, true, record.recordedAt(),
                            engine.verdict(), engine.outcome()));
                }
            }
        }
        return cells;
    }

    public CombinationView view(Combination combination) throws IOException {
        Optional<CombinationStore.RecordRow> record = record(combination);
        return new CombinationView(combination.key(), combination.employee(), combination.slot(), combination.items(),
                combination.ticket(), combination.device(), record.isPresent(),
                record.map(CombinationStore.RecordRow::recordedAt).orElse(null),
                record.map(CombinationStore.RecordRow::runId).orElse(null),
                record.map(row -> views.step(row.runId(), 1)).orElse(null));
    }

    /** The stored run of a cell under the current versions, if any visitor ran it already. */
    public Optional<CombinationStore.RecordRow> record(Combination combination) throws IOException {
        return store.find(combination.key(), versionKey(combination.employee()));
    }

    /**
     * Keeps a completed live run as the cell's record. A run that did not complete, used a development-only forced
     * decision or got no decision from the engine (unresolved: a technical failure, not a judgement) is never kept;
     * the first resolved run of a cell wins.
     */
    public boolean keep(Combination combination, String versionKey, String runId, String visitorHash) {
        Optional<ReplayStore.RunRow> run = runs.run(runId);
        if (run.isEmpty() || !"COMPLETED".equals(run.get().status()) || run.get().forcedAction() != null
                || !combination.key().equals(run.get().scenarioKey()) || store.unresolved(runId)) {
            return false;
        }
        return store.save(combination.key(), versionKey, runId, visitorHash);
    }

    private static ReplayView.Layer engineLayer(ReplayView.StepResult step) {
        return step.layers().stream().filter(layer -> "D".equals(layer.control())).findFirst()
                .orElseThrow(() -> new IllegalStateException("A stored run has no result of control D"));
    }
}
