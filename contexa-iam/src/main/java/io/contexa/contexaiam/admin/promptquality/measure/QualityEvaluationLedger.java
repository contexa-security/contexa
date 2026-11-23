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

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceEmpiricalEvalService;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Quality plan 2.1, 3.9: the evaluation ledger of the prompt governance points at the measurement summary. Once a
 * measurement of a version is done, the ledger row of that version ({@code ctxa_prompt_governance_eval_ledger}, one per
 * scope, prompt and version) is written over to name it: the reference {@code ctxa_prompt_version_measure:<id>}, the
 * measurement as the run, and the content hash of the version as the bundle measured.
 *
 * <p>The row says the version was measured ({@link #MEASURED}), not that it passed: whether a version may decide is the
 * quality gate's verdict on the measurements, read where they are kept. So the lifecycle ledger and the release gate of
 * a bundle, which take an evaluation as satisfied only when it {@code PASSED}, find what they found before. The table
 * belongs to JPA, so the row is written through its repository. Nothing is written for a measurement that is not
 * done.</p>
 */
public class QualityEvaluationLedger {

    private static final Logger log = LoggerFactory.getLogger(QualityEvaluationLedger.class);

    /** The state of an evaluation row that names a finished quality measurement. */
    public static final String MEASURED = "MEASURED";
    /** The mode of the evaluation: a quality measurement of the version on a published case set. */
    public static final String MODE = "PROMPT_QUALITY_MEASUREMENT";
    /** What wrote the row. */
    public static final String SOURCE = "PROMPT_QUALITY_MEASUREMENT";
    /** The table the reference of the row names, before the number of the measurement. */
    public static final String REFERENCE_PREFIX = "ctxa_prompt_version_measure:";

    private static final String NOT_VERIFIED = "NOT_VERIFIED";

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptGovernanceEvaluationRecordRepository evaluations;
    private final Clock clock;

    public QualityEvaluationLedger(Supplier<JdbcTemplate> jdbc, PromptGovernanceEvaluationRecordRepository evaluations,
                                   @Nullable Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.evaluations = Objects.requireNonNull(evaluations, "evaluations");
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /** The measurement as the ledger names it. */
    private record Done(long id, String scope, String prompt, int versionNumber, String contentHash,
                        String caseSetVersion, int repeats, int plannedAnswers, @Nullable String modelSetting,
                        String createdBy) {
    }

    /**
     * Writes the ledger row of the measured version over to name the measurement.
     *
     * @return whether a row was written; false when the measurement is not there or not done
     */
    public boolean record(long measureId) {
        Done done = jdbc.get().query("select id, registry_scope, prompt_key, version_number, version_content_hash,"
                + " case_set_version, repeats, planned_answers, model_setting, created_by from"
                + " ctxa_prompt_version_measure where id = ? and status = ?", (rs, row) -> new Done(rs.getLong(1),
                rs.getString(2), rs.getString(3), rs.getInt(4), rs.getString(5), rs.getString(6), rs.getInt(7),
                rs.getInt(8), rs.getString(9), rs.getString(10)), measureId, PromptQualityMeasurements.DONE)
                .stream().findFirst().orElse(null);
        if (done == null) {
            log.debug("[PromptQualityLedger] Measurement {} is not done; the evaluation ledger is left as it is",
                    measureId);
            return false;
        }
        String version = PromptVersionNames.name(done.versionNumber());
        LocalDateTime now = LocalDateTime.ofInstant(clock.instant(), ZoneId.systemDefault());
        PromptGovernanceEvaluationRecord row = evaluations
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(done.scope(), done.prompt(),
                        version)
                .orElseGet(PromptGovernanceEvaluationRecord::new);
        row.setRegistryScope(done.scope());
        row.setPromptKey(done.prompt());
        row.setPromptVersion(version);
        row.setEvaluationReference(REFERENCE_PREFIX + done.id());
        row.setEvaluationMode(MODE);
        row.setEvaluationState(MEASURED);
        row.setEmpiricalEvidenceState("SATISFIED");
        row.setPromptInjectionState(NOT_VERIFIED);
        row.setScenarioCoverageState("NOT_RECORDED");
        row.setCoveredScenarioCount(0);
        row.setRequiredScenarioCount(PromptGovernanceEmpiricalEvalService.requiredScenarioFamilies(
                PromptBundleCatalog.shared().find(done.prompt(), version).orElse(null)).size());
        row.setCoveredScenarioFamiliesJson("[]");
        row.setTevvGateState("NOT_READY");
        row.setQualityGateState(NOT_VERIFIED);
        row.setLatencyGateState(NOT_VERIFIED);
        row.setCostGateState(NOT_VERIFIED);
        row.setEvaluationSummary(truncate(summary(done, version), 2000));
        row.setEvaluatedBy(truncate(done.createdBy(), 128));
        row.setRegistrationSource(SOURCE);
        row.setBundleHash(done.contentHash());
        row.setRunReference(String.valueOf(done.id()));
        if (row.getCreatedAt() == null) {
            row.setCreatedAt(now);
        }
        row.setUpdatedAt(now);
        evaluations.saveAndFlush(row);
        log.info("[PromptQualityLedger] The evaluation ledger of {} {} in {} names measurement {}", done.prompt(),
                version, done.scope(), done.id());
        return true;
    }

    private static String summary(Done done, String version) {
        return String.format(Locale.ROOT, "Quality measurement %d of %s is done: case set %s, %d runs, %d answers,"
                        + " model setting %s. The quality gate reads its verdict from the measurement.", done.id(),
                version, done.caseSetVersion(), done.repeats(), done.plannedAnswers(),
                done.modelSetting() != null ? done.modelSetting() : "unknown");
    }

    private static String truncate(String text, int length) {
        return text.length() <= length ? text : text.substring(0, length);
    }
}
