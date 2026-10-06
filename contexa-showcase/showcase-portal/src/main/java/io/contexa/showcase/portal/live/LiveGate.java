package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.combination.Combination;
import io.contexa.showcase.portal.combination.CombinationCatalog;
import io.contexa.showcase.portal.combination.CombinationService;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.StepSummary;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.template.TemplateCurrency;

import java.io.IOException;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * The cost gate in front of every new live run (deck p.28, docs/showcase/P4-설계.md 3절). Every press of the visitor
 * runs live (docs/showcase/체험우선-설계.md, ADR-32): the human check, the daily allotment, room in the spaces and the
 * visitor and address limits must all pass, and a run that cannot start or fails for a technical reason gives its count
 * back. A refused grid cell carries its stored run, if any visitor ran it already, so the screen can show that record
 * as a record. A scenario that clones a template starts only when a template learned under the versions in force exists
 * (TEMPLATE, shown as a pause; docs/showcase/계획대조-검수.md N-8). Every outcome is counted by {@link LiveGateWatch}
 * (P5-SEC-07), and so is every finished run with or without an engine decision (N-1).
 */
public class LiveGate {

    public sealed interface Outcome permits Started, Refused {
    }

    public record Started(LiveRun run) implements Outcome {
    }

    /**
     * @param reason   TEMPLATE, TURNSTILE_*, ALLOTMENT, BUSY, VISITOR_LIMIT or ADDRESS_LIMIT
     * @param fallback the refused cell's stored run, shown as a record instead; null without one
     */
    public record Refused(String reason, CombinationService.CombinationView fallback) implements Outcome {
    }

    private final CombinationService combinations;
    private final TurnstileVerifier turnstile;
    private final LiveAllotment allotment;
    private final LiveQuota quota;
    private final LiveRuns live;
    private final LiveGateWatch watch;
    private final TemplateCurrency templates;

    public LiveGate(CombinationService combinations, TurnstileVerifier turnstile, LiveAllotment allotment,
                    LiveQuota quota, LiveRuns live, LiveGateWatch watch, TemplateCurrency templates) {
        this.templates = templates;
        this.combinations = combinations;
        this.turnstile = turnstile;
        this.allotment = allotment;
        this.quota = quota;
        this.live = live;
        this.watch = watch;
    }

    public Outcome combination(String visitor, String address, Combination cell, String turnstileToken)
            throws IOException {
        String versionKey = combinations.versionKey(cell.employee());
        Outcome outcome = start(visitor, address, CombinationCatalog.scenario(cell), turnstileToken, summary -> {
            if ("COMPLETED".equals(summary.status())) {
                combinations.keep(cell, versionKey, summary.runId(), visitor);
            }
        });
        if (outcome instanceof Refused refused && combinations.record(cell).isPresent()) {
            return new Refused(refused.reason(), combinations.view(cell));
        }
        return outcome;
    }

    /** A scenario of the "try it yourself" page; it is not a grid cell, so nothing is reused or kept. */
    public Outcome scenario(String visitor, String address, ScenarioDefinition scenario, String turnstileToken)
            throws IOException {
        return start(visitor, address, scenario, turnstileToken, summary -> {
        });
    }

    private Outcome start(String visitor, String address, ScenarioDefinition scenario, String turnstileToken,
                          Consumer<RunSummary> keep) throws IOException {
        Optional<LiveRun> current = live.current(visitor);
        if (current.isPresent() && current.get().active()) {
            watch.passed(LiveGateWatch.RESUMED);
            return new Started(current.get());
        }
        if (scenario.template() && templates.current(scenario.protagonist()).isEmpty()) {
            return refuse("TEMPLATE");
        }
        TurnstileVerifier.Result check = turnstile.verify(turnstileToken, address);
        if (!check.passed()) {
            return refuse(check.reason());
        }
        if (allotment.state().exhausted()) {
            return refuse("ALLOTMENT");
        }
        if (!live.hasRoom()) {
            return refuse("BUSY");
        }
        LiveQuota.Refusal refusal = quota.take(visitor, address);
        if (refusal != null) {
            return refuse(refusal.name());
        }
        try {
            LiveRun run = live.start(visitor, scenario, summary -> {
                watch.finished(summary.steps().stream().anyMatch(StepSummary::unresolved));
                if (!"COMPLETED".equals(summary.status())) {
                    quota.giveBack(visitor, address);
                }
                keep.accept(summary);
            });
            watch.passed(LiveGateWatch.STARTED);
            return new Started(run);
        } catch (LiveRuns.Busy e) {
            quota.giveBack(visitor, address);
            return refuse("BUSY");
        }
    }

    private Refused refuse(String reason) {
        watch.refused(reason);
        return new Refused(reason, null);
    }
}
