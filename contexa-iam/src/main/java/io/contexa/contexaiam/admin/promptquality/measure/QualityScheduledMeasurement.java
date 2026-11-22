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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityComparison;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurement;
import io.contexa.contexacore.std.components.prompt.quality.QualityMetric;
import io.contexa.contexacore.std.components.prompt.quality.QualityNoise;
import io.contexa.contexacore.std.components.prompt.quality.QualityRate;
import io.contexa.contexacore.std.components.prompt.quality.QualityRemeasureComparison;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.support.CronExpression;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Plan 3.6: the version in use measured again, on schedule (weekly by default) and when the model setting changed, on
 * the case set the measurements of its scope run on, and told when it came out worse than its measurement before.
 *
 * <ul>
 * <li>The schedule asks {@link QualityAutoMeasurement} for the version each scope decides with. The same version, case
 * set and settings measured before give no new answer, so a new measurement starts only for what is new: a case set
 * published with new cases (the cases measured before are used again) or settings that change an answer.</li>
 * <li>Every watch looks for a version in use measured under other settings only and measures it once, and compares each
 * measurement Contexa took again, once it is done, with the version's measurement before
 * ({@link QualityRemeasureComparison}). The comparison is kept on the measurement, so the state of quality shows what
 * to check; one worse or changed is logged as a warning. There is no notification of administrators in this product
 * to send it to.</li>
 * <li>One server runs each: the schedule and the watch hold locks of the scheduled work of Contexa, the measurer
 * decides what to start under its own lock and starts nothing that is queued or done, and a comparison is kept once.</li>
 * </ul>
 */
public class QualityScheduledMeasurement {

    private static final Logger log = LoggerFactory.getLogger(QualityScheduledMeasurement.class);

    /** The schedule by default: every Sunday at 02:00 UTC. */
    public static final String DEFAULT_CRON = "0 0 2 * * SUN";
    /** The property that sets the schedule; "-" turns it off. */
    public static final String CRON_PROPERTY = "contexa.pqa.oss.quality.remeasure.cron";
    /** The lock under which one server measures again on schedule. */
    public static final String SCHEDULE_LOCK = "contexaPromptQualityScheduledMeasure";
    /** The lock under which one server watches for changed settings and finished measurements. */
    public static final String WATCH_LOCK = "contexaPromptQualityRemeasureWatch";
    /** The reasons whose measurements are compared with the measurement before. */
    static final List<String> COMPARED_REASONS = List.of(QualityAutoMeasurement.Reason.SCHEDULED.name(),
            QualityAutoMeasurement.Reason.SETTINGS_CHANGED.name());
    private static final int COMPARED_AT_ONCE = 20;

    /**
     * The comparison kept on a measurement taken again.
     *
     * @param comparedMeasureId the measurement before, or null when there was none
     */
    public record Kept(long measureId, String scope, String prompt, int versionNumber, String startReason,
                       @Nullable Long comparedMeasureId, QualityRemeasureComparison.Verdict verdict,
                       Map<String, Object> detail, Instant comparedAt) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final QualityAutoMeasurement auto;
    private final Supplier<PromptQualityMeasurements> measurements;
    private final PromptQualityCases cases;
    private final String cron;
    private final double significance;
    private final ObjectMapper json;
    private final Clock clock;

    /**
     * @param cron         the schedule, a Spring cron expression in UTC; "-" or none turns it off
     * @param significance the level of the exact test of the paired comparison (the gate's)
     */
    public QualityScheduledMeasurement(Supplier<JdbcTemplate> jdbc, QualityAutoMeasurement auto,
                                       Supplier<PromptQualityMeasurements> measurements, PromptQualityCases cases,
                                       @Nullable String cron, double significance, ObjectMapper json,
                                       @Nullable Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.auto = Objects.requireNonNull(auto, "auto");
        this.measurements = measurements != null ? measurements : () -> null;
        this.cases = Objects.requireNonNull(cases, "cases");
        this.cron = cron != null && !cron.isBlank() ? cron.trim() : "-";
        this.significance = significance;
        this.json = Objects.requireNonNull(json, "json");
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /** Plan 3.6: the version in use of every scope, measured again on schedule, by one server. */
    @Scheduled(scheduler = "contexaTaskScheduler", cron = "${" + CRON_PROPERTY + ":" + DEFAULT_CRON + "}", zone = "UTC")
    @SchedulerLock(name = SCHEDULE_LOCK, lockAtMostFor = "PT30M", lockAtLeastFor = "PT1M")
    public void remeasureOnSchedule() {
        try {
            List<QualityAutoMeasurement.Result> results = auto.remeasureInUse(QualityAutoMeasurement.Reason.SCHEDULED);
            log.info("[PromptQualityRemeasure] Scheduled measurement of the versions in use: {}", results);
        }
        catch (RuntimeException failure) {
            log.error("[PromptQualityRemeasure] The scheduled measurement of the versions in use failed", failure);
        }
    }

    /**
     * Plan 3.6: a version in use measured under other settings only is measured again, and the measurements taken
     * again that are done are compared with the measurement before; by one server.
     */
    @Scheduled(scheduler = "contexaTaskScheduler", fixedDelayString = "PT10M", initialDelayString = "PT2M")
    @SchedulerLock(name = WATCH_LOCK, lockAtMostFor = "PT9M", lockAtLeastFor = "PT30S")
    public void watch() {
        try {
            auto.remeasureInUse(QualityAutoMeasurement.Reason.SETTINGS_CHANGED);
            compareFinished();
        }
        catch (RuntimeException failure) {
            log.error("[PromptQualityRemeasure] Watching the measurements taken again failed", failure);
        }
    }

    /** When the schedule measures next, or null when it is off. */
    @Nullable
    public Instant nextScheduled() {
        if ("-".equals(cron)) {
            return null;
        }
        try {
            return Optional.ofNullable(CronExpression.parse(cron).next(clock.instant().atZone(ZoneOffset.UTC)))
                    .map(next -> next.toInstant()).orElse(null);
        }
        catch (IllegalArgumentException unreadable) {
            return null;
        }
    }

    /**
     * Compares each measurement taken again on schedule or after a change of the model setting that is done and not
     * compared yet with the version's measurement done before it; returns how many were compared here.
     */
    public int compareFinished() {
        PromptQualityMeasurements runner = measurements.get();
        if (runner == null) {
            return 0;
        }
        List<Long> waiting = jdbc.get().queryForList("select id from ctxa_prompt_version_measure where status = ? and"
                + " compared_at is null and start_reason in (?, ?) order by finished_at, id limit ?", Long.class,
                PromptQualityMeasurements.DONE, COMPARED_REASONS.get(0), COMPARED_REASONS.get(1), COMPARED_AT_ONCE);
        int compared = 0;
        for (Long id : waiting) {
            try {
                if (compare(runner, id)) {
                    compared++;
                }
            }
            catch (RuntimeException failure) {
                log.error("[PromptQualityRemeasure] Measurement {} could not be compared with the one before", id,
                        failure);
            }
        }
        return compared;
    }

    private boolean compare(PromptQualityMeasurements runner, long id) {
        PromptQualityMeasurements.Measure later = runner.find(id).orElse(null);
        if (later == null) {
            return false;
        }
        Long previousId = jdbc.get().queryForList("select id from ctxa_prompt_version_measure where registry_scope = ?"
                + " and prompt_key = ? and version_number = ? and version_content_hash = ? and status = ? and id <> ?"
                + " and (created_at < ? or (created_at = ? and id < ?)) order by created_at desc, id desc limit 1",
                Long.class, later.scope(), later.prompt(), later.versionNumber(), later.versionContentHash(),
                PromptQualityMeasurements.DONE, id, Timestamp.from(later.createdAt()),
                Timestamp.from(later.createdAt()), id).stream().findFirst().orElse(null);
        PromptQualityMeasurements.Measure previous = previousId != null ? runner.find(previousId).orElse(null) : null;
        QualityRemeasureComparison comparison = previous == null ? QualityRemeasureComparison.notCompared()
                : QualityRemeasureComparison.compare(casesOf(previous), measurement(runner, previous),
                casesOf(later), measurement(runner, later), QualityNoise.unknown(), significance);
        Map<String, Object> detail = detail(comparison, previous, later);
        detail.put("changedSettings", previous != null ? QualityModelSetting.changed(runner.settingsOf(previous.id()),
                runner.settingsOf(later.id())) : Map.of());
        int kept = jdbc.get().update("update ctxa_prompt_version_measure set compared_measure_id = ?, comparison = ?,"
                + " comparison_detail = ?, compared_at = ? where id = ? and compared_at is null", previousId,
                comparison.verdict().name(), write(detail), Timestamp.from(clock.instant()), id);
        if (kept != 1) {
            return false;
        }
        if (comparison.verdict() == QualityRemeasureComparison.Verdict.WORSE
                || comparison.verdict() == QualityRemeasureComparison.Verdict.CHANGED) {
            log.warn("[PromptQualityRemeasure] {} {} in {} measured again ({}) came out {} against measurement {}:"
                            + " newlyMissed={}, newlyStopped={}, addedMissed={}, addedStopped={}, newlyFailedGraded={}",
                    later.prompt(), later.versionName(), later.scope(), later.startReason(), comparison.verdict(),
                    previousId, comparison.changes().newlyMissed(), comparison.changes().newlyStopped(),
                    comparison.addedMissed(), comparison.addedStopped(), comparison.newlyFailedGraded());
        }
        else {
            log.info("[PromptQualityRemeasure] {} {} in {} measured again ({}) came out {} against measurement {}",
                    later.prompt(), later.versionName(), later.scope(), later.startReason(), comparison.verdict(),
                    previousId);
        }
        return true;
    }

    /** The latest comparison kept on a measurement of the version taken again, or empty. */
    public Optional<Kept> latestComparison(String scope, String prompt, int versionNumber) {
        return jdbc.get().query("select id, registry_scope, prompt_key, version_number, start_reason,"
                + " compared_measure_id, comparison, comparison_detail, compared_at from ctxa_prompt_version_measure"
                + " where registry_scope = ? and prompt_key = ? and version_number = ? and compared_at is not null"
                + " order by compared_at desc, id desc limit 1", (rs, row) -> new Kept(rs.getLong(1),
                rs.getString(2), rs.getString(3), rs.getInt(4), rs.getString(5), (Long) rs.getObject(6),
                QualityRemeasureComparison.Verdict.valueOf(rs.getString(7)), read(rs.getString(8)),
                rs.getTimestamp(9).toInstant()), scope, prompt, versionNumber).stream().findFirst();
    }

    private List<QualityCase> casesOf(PromptQualityMeasurements.Measure measure) {
        return cases.published(measure.caseSetId()).map(set -> cases.read(set).cases().cases()).orElse(List.of());
    }

    private static QualityMeasurement measurement(PromptQualityMeasurements runner,
                                                  PromptQualityMeasurements.Measure measure) {
        return new QualityMeasurement(measure.versionName(), measure.modelSettingOrSettings(),
                measure.caseSetVersion(), measure.repeats(), runner.answers(measure.id()));
    }

    /** The figures of the comparison: the cases it read, those that moved, and each rate before and after. */
    private static Map<String, Object> detail(QualityRemeasureComparison comparison,
                                              @Nullable PromptQualityMeasurements.Measure previous,
                                              PromptQualityMeasurements.Measure later) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("verdict", comparison.verdict().name());
        detail.put("startReason", later.startReason());
        detail.put("previousCaseSetVersion", previous != null ? previous.caseSetVersion() : null);
        detail.put("laterCaseSetVersion", later.caseSetVersion());
        detail.put("previousModelSetting", previous != null ? previous.modelSettingOrSettings() : null);
        detail.put("laterModelSetting", later.modelSettingOrSettings());
        detail.put("sharedCases", comparison.sharedCases());
        detail.put("addedCases", comparison.addedCases());
        detail.put("newlyMissed", comparison.changes().newlyMissed());
        detail.put("newlyStopped", comparison.changes().newlyStopped());
        detail.put("newlyCaught", comparison.changes().newlyCaught());
        detail.put("newlyReleased", comparison.changes().newlyReleased());
        detail.put("addedMissed", comparison.addedMissed());
        detail.put("addedStopped", comparison.addedStopped());
        detail.put("newlyFailedGraded", comparison.newlyFailedGraded());
        Map<String, Object> rates = new LinkedHashMap<>();
        for (QualityMetric metric : QualityMetric.values()) {
            QualityRate before = comparison.previousRates().get(metric);
            QualityRate after = comparison.laterRates().get(metric);
            QualityComparison paired = comparison.comparisons().get(metric);
            if (before == null && after == null && paired == null) {
                continue;
            }
            Map<String, Object> rate = new LinkedHashMap<>();
            rate.put("before", before != null ? List.of(before.events(), before.trials()) : null);
            rate.put("after", after != null ? List.of(after.events(), after.trials()) : null);
            rate.put("pairedVerdict", paired != null ? paired.verdict().name() : null);
            rate.put("pairedCases", paired != null ? paired.pairedCases() : 0);
            rates.put(metric.name(), rate);
        }
        detail.put("rates", rates);
        return detail;
    }

    private String write(Map<String, Object> detail) {
        try {
            return json.writeValueAsString(detail);
        }
        catch (JsonProcessingException failure) {
            throw new IllegalStateException("The comparison could not be written", failure);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> read(@Nullable String text) {
        if (text == null || text.isBlank()) {
            return Map.of();
        }
        try {
            return json.readValue(text, Map.class);
        }
        catch (JsonProcessingException unreadable) {
            return Map.of();
        }
    }
}
