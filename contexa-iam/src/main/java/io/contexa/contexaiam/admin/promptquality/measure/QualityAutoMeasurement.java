/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.promptquality.measure;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.std.components.prompt.quality.QualityShippedMeasurements;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionResolver;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Supplier;

/**
 * The measurements Contexa starts by itself (plan 3.4): the version that decides outside the release gate (the one the
 * setting names, or the newest Contexa version an upgrade brought) and the version in use with no measurement right
 * after an upgrade of an installation in use are measured once. A version is measured once for its content, the case
 * set and the server settings that change an answer: not again while a measurement of it is queued, running or done,
 * and not again automatically once Contexa tried (a refused or failed one is left to an administrator). A Contexa
 * version the product shipped a measurement of, taken the same way, is not measured. The measurement waits in the
 * line, within the call limit and the concurrency of every measurement; the servers of one database decide what to
 * start under one lock, so one of them starts it. With nothing published in the scope, the default set of the product
 * is published first and measured on.
 *
 * <p>Plan 3.6: the version in use is measured again on schedule and when the model setting changed. The same version,
 * case set and settings measured before give no new answer (every answer is used again), so the schedule measures only
 * what is new: a case set published with new cases, or settings that change an answer; it tries a measurement it
 * could not finish again. A changed model setting is measured once.</p>
 */
public class QualityAutoMeasurement implements PromptVersionResolver.OutsideGateListener, AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(QualityAutoMeasurement.class);

    /** Who the measurements and the published default sets Contexa starts by itself are made by. */
    public static final String ACTOR = "contexa-auto-measure";
    /** The lock under which the servers of one database decide what to measure. */
    public static final String LOCK_NAME = "contexaPromptQualityAutoMeasure";
    private static final Duration LOCK_FOR = Duration.ofMinutes(1);
    private static final int BUSY_TRIES = 5;
    private static final Duration BUSY_WAIT = Duration.ofSeconds(2);
    private static final String ACTIVE_STATES = PromptBundleState.sqlList(PromptBundleState.ACTIVE);

    /** Why Contexa measures a version by itself. */
    public enum Reason {
        /** It decides outside the release gate: the setting names it, or it is the newest Contexa version. */
        OUTSIDE_GATE,
        /** It is the version in use and has no measurement (right after an upgrade). */
        BASELINE,
        /** Plan 3.6: the version in use, measured again on schedule. */
        SCHEDULED,
        /** Plan 3.6: the version in use, measured only under other settings that change an answer. */
        SETTINGS_CHANGED
    }

    /** What an automatic measurement came to. */
    public enum Outcome {
        QUEUED, MEASURED_ALREADY, QUEUED_ALREADY, TRIED_ONCE, SHIPPED, REFUSED, NO_RUNNER, BUSY
    }

    /**
     * @param measureId the measurement queued, or the one already there; null when there is none
     * @param detail    why, as a code (a refusal of the measurement, or why nothing is measured)
     */
    public record Result(Outcome outcome, Long measureId, String detail) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptVersionService versions;
    private final PromptQualityCases cases;
    private final Supplier<PromptQualityMeasurements> measurements;
    private final JdbcPromptVersionCatalog catalog;
    private final QualityShippedMeasurements shipped;
    private final QualityMeasureLock lock;
    private final ExecutorService executor;

    /**
     * @param measurements the measurement runner; a supplier of null when this application cannot replay decisions
     * @param catalog      what reads the version each scope decides with, and where it comes from
     * @param lock         the lock the servers of one database share, or the lock of this server alone
     */
    public QualityAutoMeasurement(Supplier<JdbcTemplate> jdbc, PromptVersionService versions,
                                  PromptQualityCases cases, Supplier<PromptQualityMeasurements> measurements,
                                  JdbcPromptVersionCatalog catalog, QualityShippedMeasurements shipped,
                                  QualityMeasureLock lock) {
        this(jdbc, versions, cases, measurements, catalog, shipped, lock, Executors.newSingleThreadExecutor(work -> {
            Thread thread = new Thread(work, "contexa-prompt-quality-auto-measure");
            thread.setDaemon(true);
            return thread;
        }));
    }

    QualityAutoMeasurement(Supplier<JdbcTemplate> jdbc, PromptVersionService versions, PromptQualityCases cases,
                           Supplier<PromptQualityMeasurements> measurements, JdbcPromptVersionCatalog catalog,
                           QualityShippedMeasurements shipped, QualityMeasureLock lock, ExecutorService executor) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.versions = Objects.requireNonNull(versions, "versions");
        this.cases = Objects.requireNonNull(cases, "cases");
        this.measurements = measurements != null ? measurements : () -> null;
        this.catalog = catalog;
        this.shipped = shipped != null ? shipped : QualityShippedMeasurements.none();
        this.lock = Objects.requireNonNull(lock, "lock");
        this.executor = Objects.requireNonNull(executor, "executor");
    }

    /**
     * The case set measurements of the scope run on: the latest one published there, else the default set of the
     * product, published now for it.
     */
    public PromptQualityCases.PublishedSet caseSet(String scope, String prompt) {
        return cases.latestPublished(scope, prompt).orElseGet(() -> {
            PromptQualityCases.PublishedSet published = cases.publishDefault(scope, prompt, ACTOR);
            log.info("[PromptQualityAutoMeasure] Nothing was published in {}: the default case set {} is published"
                    + " to measure on", scope, published.version());
            return published;
        });
    }

    /** Measures the version once, as plan 3.4 says, unless it is measured, waits, was tried or was shipped. */
    public Result request(String scope, String prompt, String version, Reason reason) {
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null) {
            return new Result(Outcome.NO_RUNNER, null, MeasuredQualityGateSource.NO_MEASUREMENT_RUNNER);
        }
        OptionalInt number = PromptVersionNames.number(version);
        if (!PromptQualityCases.offeredFor(prompt) || number.isEmpty()) {
            return new Result(Outcome.REFUSED, null, PromptQualityMeasurements.Refusal.PROMPT.name());
        }
        String scopeName = scopeOf(scope);
        Optional<QualityMeasureLock.Held> held = lock.acquire(LOCK_FOR);
        if (held.isEmpty()) {
            return new Result(Outcome.BUSY, null, null);
        }
        try {
            PromptVersionRecord record = versions.find(scopeName, prompt, number.getAsInt())
                    .filter(found -> !found.hidden()).orElse(null);
            if (record == null) {
                return new Result(Outcome.REFUSED, null, PromptQualityMeasurements.Refusal.VERSION.name());
            }
            PromptQualityCases.PublishedSet set = caseSet(scopeName, prompt);
            String now = runner.settingsHash();
            List<PromptQualityMeasurements.Measure> taken = runner.recent(scopeName, prompt, record.number(),
                    MeasuredQualityGateSource.RECENT).stream()
                    .filter(row -> row.caseSetId() == set.id() && row.versionContentHash().equals(record.contentHash())
                            && row.settingsHash().equals(now))
                    .toList();
            Optional<Result> already = already(taken, reason);
            if (already.isPresent()) {
                return already.get();
            }
            if (shipped.find(prompt, record.contentHash(), set.version(), now).isPresent()) {
                return new Result(Outcome.SHIPPED, null, MeasuredQualityGateSource.SHIPPED);
            }
            long id = runner.start(scopeName, prompt, record.number(), set.id(), null, ACTOR, reason.name());
            log.info("[PromptQualityAutoMeasure] {} {} in {} is measured automatically ({}) on case set {}:"
                    + " measurement {}", prompt, record.name(), scopeName, reason, set.version(), id);
            return new Result(Outcome.QUEUED, id, reason.name());
        }
        catch (PromptQualityMeasurements.RefusedException refused) {
            log.warn("[PromptQualityAutoMeasure] The automatic measurement of {} {} in {} ({}) was refused: {} {}",
                    prompt, version, scopeName, reason, refused.refusal(), refused.getMessage());
            return new Result(Outcome.REFUSED, null, refused.refusal().name());
        }
        finally {
            held.get().release();
        }
    }

    /**
     * A measurement that says the version needs none now: one done, one waiting, or one Contexa tried already; the
     * schedule tries again a measurement it could not finish.
     */
    private static Optional<Result> already(List<PromptQualityMeasurements.Measure> taken, Reason reason) {
        for (PromptQualityMeasurements.Measure row : taken) {
            if (PromptQualityMeasurements.DONE.equals(row.status())) {
                return Optional.of(new Result(Outcome.MEASURED_ALREADY, row.id(), null));
            }
        }
        for (PromptQualityMeasurements.Measure row : taken) {
            if (PromptQualityMeasurements.QUEUED.equals(row.status())
                    || PromptQualityMeasurements.RUNNING.equals(row.status())) {
                return Optional.of(new Result(Outcome.QUEUED_ALREADY, row.id(), null));
            }
        }
        for (PromptQualityMeasurements.Measure row : taken) {
            if (ACTOR.equals(row.createdBy()) && reason != Reason.SCHEDULED) {
                return Optional.of(new Result(Outcome.TRIED_ONCE, row.id(), row.status()));
            }
        }
        return Optional.empty();
    }

    /**
     * Asks for the measurement on this measurer's own thread: the caller goes on at once. While another server holds
     * the lock it is asked again a few times.
     */
    public void requestLater(String scope, String prompt, String version, Reason reason) {
        submit(() -> {
            for (int tried = 1; ; tried++) {
                Result result = request(scope, prompt, version, reason);
                if (result.outcome() != Outcome.BUSY || tried >= BUSY_TRIES) {
                    if (result.outcome() == Outcome.BUSY) {
                        log.info("[PromptQualityAutoMeasure] Another server decides the measurements; {} {} is left to"
                                + " it", prompt, version);
                    }
                    return;
                }
                Thread.sleep(BUSY_WAIT.toMillis());
            }
        });
    }

    /** Plan 3.4: a version found deciding outside the gate without a measurement here is measured. */
    @Override
    public void decidesOutsideGate(String prompt, String version, PromptBundleSelectionSource source,
                                   QualityMeasurementState state) {
        if (state != QualityMeasurementState.UNMEASURABLE) {
            requestLater(PromptVersionService.PLATFORM_SCOPE, prompt, version, Reason.OUTSIDE_GATE);
        }
    }

    /**
     * Plan 3.4, at the start of the application: in the platform scope and each scope with a label of the security
     * decision, the version deciding outside the gate is measured, and so is a labelled version with no measurement on
     * the case set (right after an upgrade). Plan 3.6: a labelled version measured under other settings only is
     * measured again, once.
     */
    public List<Result> measureDecidingVersions() {
        List<Result> results = new ArrayList<>();
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null || catalog == null) {
            log.debug("[PromptQualityAutoMeasure] No measurement runner: nothing is measured automatically");
            return results;
        }
        String prompt = SecurityDecisionPromptDocument.PROMPT;
        for (String scope : scopes(prompt)) {
            PromptBundleSelection selection = catalog.decidingSelection(scope, prompt);
            String version = selection != null ? selection.bundleVersion() : null;
            if (PromptVersionNames.number(version).isEmpty()) {
                continue;
            }
            if (selection.source() == PromptBundleSelectionSource.CONFIGURATION
                    || selection.source() == PromptBundleSelectionSource.BUILD_DEFAULT) {
                results.add(request(scope, prompt, version, Reason.OUTSIDE_GATE));
                continue;
            }
            QualityMeasurementState state = labelled(runner, scope, prompt, version);
            if (state == QualityMeasurementState.MISSING) {
                results.add(request(scope, prompt, version, Reason.BASELINE));
            }
            else if (state == QualityMeasurementState.STALE) {
                // Plan 3.6: the model setting changed since it was measured, so it is measured again.
                log.warn("[PromptQualityAutoMeasure] {} {}, used for decisions in {}, was measured under other server"
                        + " settings only: it is measured again", prompt, version, scope);
                results.add(request(scope, prompt, version, Reason.SETTINGS_CHANGED));
            }
        }
        return results;
    }

    /**
     * Plan 3.6: the version each scope decides with, measured again for the reason: on schedule, every one; after a
     * change of the model setting, the labelled ones measured under other settings only (a version outside the gate
     * is measured under the present settings by {@link #measureDecidingVersions()}).
     */
    public List<Result> remeasureInUse(Reason reason) {
        List<Result> results = new ArrayList<>();
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null || catalog == null) {
            return results;
        }
        String prompt = SecurityDecisionPromptDocument.PROMPT;
        for (String scope : scopes(prompt)) {
            PromptBundleSelection selection = catalog.decidingSelection(scope, prompt);
            String version = selection != null ? selection.bundleVersion() : null;
            if (PromptVersionNames.number(version).isEmpty()) {
                continue;
            }
            if (reason == Reason.SETTINGS_CHANGED && labelled(runner, scope, prompt, version)
                    != QualityMeasurementState.STALE) {
                continue;
            }
            results.add(request(scope, prompt, version, reason));
        }
        return results;
    }

    /** Runs {@link #measureDecidingVersions()} on this measurer's own thread. */
    public void measureDecidingVersionsLater() {
        submit(this::measureDecidingVersions);
    }

    /**
     * What the labelled version has on the case set: a measurement under the present settings (done, waiting or tried
     * already), finished ones under other settings only (stale), or none.
     */
    private QualityMeasurementState labelled(PromptQualityMeasurements runner, String scope, String prompt,
                                             String version) {
        PromptVersionRecord record = versions.find(scope, prompt, PromptVersionNames.number(version).getAsInt())
                .orElse(null);
        Optional<PromptQualityCases.PublishedSet> set = cases.latestPublished(scope, prompt);
        if (record == null || set.isEmpty()) {
            return QualityMeasurementState.MISSING;
        }
        String now = runner.settingsHash();
        boolean stale = false;
        for (PromptQualityMeasurements.Measure row : runner.recent(scope, prompt, record.number(),
                MeasuredQualityGateSource.RECENT)) {
            if (row.caseSetId() != set.get().id() || !row.versionContentHash().equals(record.contentHash())) {
                continue;
            }
            if (row.settingsHash().equals(now)) {
                return QualityMeasurementState.MEASURED;
            }
            stale = stale || PromptQualityMeasurements.DONE.equals(row.status());
        }
        if (!stale && shipped.find(prompt, record.contentHash(), set.get().version(), now).isPresent()) {
            return QualityMeasurementState.MEASURED;
        }
        return stale ? QualityMeasurementState.STALE : QualityMeasurementState.MISSING;
    }

    /** The platform scope and every scope with a label of the prompt. */
    private Set<String> scopes(String prompt) {
        Set<String> scopes = new LinkedHashSet<>();
        scopes.add(PromptVersionService.PLATFORM_SCOPE);
        scopes.addAll(jdbc.get().queryForList("select distinct registry_scope from ctxa_prompt_governance_registry"
                + " where prompt_key = ? and upper(release_status) in (" + ACTIVE_STATES + ") order by registry_scope",
                String.class, prompt));
        return scopes;
    }

    private interface Work {
        void run() throws InterruptedException;
    }

    private void submit(Work work) {
        try {
            executor.execute(() -> {
                try {
                    work.run();
                }
                catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                catch (RuntimeException failure) {
                    log.error("[PromptQualityAutoMeasure] An automatic measurement could not be asked for", failure);
                }
            });
        }
        catch (RejectedExecutionException closing) {
            log.info("[PromptQualityAutoMeasure] Closing: the automatic measurement is left to the next start");
        }
    }

    private static String scopeOf(String scope) {
        return scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }
}
