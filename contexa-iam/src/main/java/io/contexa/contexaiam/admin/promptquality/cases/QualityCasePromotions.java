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
package io.contexa.contexaiam.admin.promptquality.cases;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Evaluation;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.EvaluationSaved;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustDecisionRecords;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;
import org.springframework.transaction.support.TransactionOperations;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Quality plan 3.6: the decisions of the operation made labelled cases. From the decision detail, an administrator
 * evaluates a decision and sets its right answer in one step; from a trial, a sealed decision the two versions
 * decided differently is made a case with the answer an administrator sets. A decision is made a case only from its
 * seal, which holds the input the replay reads: a decision that is not sealed is refused as such. A case promoted
 * from a decision the second analysis decided is marked and counted apart ({@link PromptQualityCases.Kept}).
 */
public class QualityCasePromotions {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;

    /**
     * A case made of a decision.
     *
     * @param evaluation the evaluation kept with it, or null when it came from a trial
     */
    public record Promoted(PromptQualityCases.Kept kept, String sealedPackageId, @Nullable String observationId,
                           @Nullable EvaluationSaved evaluation) {
    }

    /** A sealed decision the two versions of a trial decided with different actions. */
    public record Divergent(String sealedPackageId, @Nullable String requestId, @Nullable String observationId,
                            String referenceAction, String candidateAction) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptQualityCases cases;
    private final SealedEvidencePackageRepository packages;
    private final ZeroTrustDecisionRecords decisions;
    private final Supplier<PromptVersionTrials> trials;
    private final TransactionOperations transactions;

    /**
     * @param decisions    the decision records, which keep the evaluation; none when the console is not here
     * @param trials       the trials of prompt versions; a supplier of null when there are none
     * @param transactions what keeps the evaluation and the case as one, or none
     */
    public QualityCasePromotions(Supplier<JdbcTemplate> jdbc, PromptQualityCases cases,
                                 SealedEvidencePackageRepository packages, @Nullable ZeroTrustDecisionRecords decisions,
                                 @Nullable Supplier<PromptVersionTrials> trials,
                                 @Nullable TransactionOperations transactions) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.cases = Objects.requireNonNull(cases, "cases");
        this.packages = Objects.requireNonNull(packages, "packages");
        this.decisions = decisions;
        this.trials = trials != null ? trials : () -> null;
        this.transactions = transactions != null ? transactions : TransactionOperations.withoutTransaction();
    }

    /**
     * Quality plan 3.6: evaluates the decision and makes it a case with the right answer the administrator sets, both
     * or neither. The decision's sealed package is its input; the case names the package and holds the person's data
     * (plan 3.2).
     *
     * @param scope the scope of the prompt versions the case is kept in, or null for the platform
     * @throws PromptQualityCases.RefusedException when there is no such decision ({@code NOT_FOUND}), it is not sealed
     *                                             ({@code NOT_SEALED}), or the answer or the input cannot make a case
     * @throws IllegalArgumentException            when the evaluation says neither valid nor invalid, or names no
     *                                             known reason
     */
    public Promoted fromEvaluation(@Nullable String scope, String observationId, Evaluation evaluation,
                                   QualityCaseExpectation expectation, QualityCaseGrade grade, String actor) {
        if (decisions == null) {
            throw new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.NOT_FOUND,
                    "The decision records are not in this application");
        }
        if (evaluation == null || evaluation.valid() == null) {
            throw new IllegalArgumentException("An evaluation says whether the decision was valid");
        }
        Integer found = jdbc.get().queryForObject("select count(*) from ctxa_ai_security_decision_observation where"
                + " observation_id = ?", Integer.class, observationId);
        if (found == null || found == 0) {
            throw new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.NOT_FOUND,
                    "There is no decision " + observationId);
        }
        SealedEvidencePackage sealed = sealed(decisions.sealedPackageOf(observationId), "The decision "
                + observationId);
        Object[] result = new Object[2];
        transactions.executeWithoutResult(status -> {
            EvaluationSaved saved = decisions.evaluate(observationId, evaluation, actor);
            if (saved == null) {
                throw new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.NOT_FOUND,
                        "There is no decision " + observationId);
            }
            result[0] = saved;
            result[1] = cases.promote(scope, PROMPT, sealed, null, null, expectation, grade, actor);
        });
        return new Promoted((PromptQualityCases.Kept) result[1], sealed.getPackageId(), observationId,
                (EvaluationSaved) result[0]);
    }

    /** Quality plan 3.6: the sealed decisions the two versions of the trial decided with different actions. */
    public List<Divergent> divergent(long trialId) {
        Map<String, String[]> actions = new LinkedHashMap<>();
        PromptVersionTrials.Trial trial = trial(trialId);
        jdbc.get().query("select sealed_package_id, observation_id, version_number, action from"
                + " ctxa_prompt_version_trial_case where trial_id = ? and sealed_package_id is not null order by id",
                rs -> {
                    String[] pair = actions.computeIfAbsent(rs.getString(1), key -> new String[3]);
                    pair[2] = pair[2] != null ? pair[2] : rs.getString(2);
                    int number = rs.getInt(3);
                    if (number == trial.candidate()) {
                        pair[1] = rs.getString(4);
                    }
                    else if (number == trial.reference()) {
                        pair[0] = rs.getString(4);
                    }
                }, trialId);
        List<Divergent> divergent = new ArrayList<>();
        actions.forEach((packageId, pair) -> {
            if (pair[0] != null && pair[1] != null && !pair[0].equals(pair[1])) {
                String request = jdbc.get().queryForList("select correlation_id from ctxa_sealed_evidence_package"
                        + " where package_id = ?", String.class, packageId).stream().findFirst().orElse(null);
                divergent.add(new Divergent(packageId, request, pair[2], pair[0], pair[1]));
            }
        });
        return divergent;
    }

    /**
     * Quality plan 3.6: makes a sealed decision the two versions of the trial decided with different actions a case of
     * the trial's scope, with the right answer the administrator sets.
     *
     * @throws PromptQualityCases.RefusedException when there is no such trial ({@code NOT_FOUND}), the two versions did
     *                                             not decide the package differently ({@code NOT_DIVERGENT}), it is
     *                                             not sealed ({@code NOT_SEALED}), or the answer cannot make a case
     */
    public Promoted fromTrial(long trialId, String sealedPackageId, QualityCaseExpectation expectation,
                              QualityCaseGrade grade, String actor) {
        PromptVersionTrials.Trial trial = trial(trialId);
        Divergent pair = divergent(trialId).stream().filter(one -> one.sealedPackageId().equals(sealedPackageId))
                .findFirst().orElseThrow(() -> new PromptQualityCases.RefusedException(
                        PromptQualityCases.Refusal.NOT_DIVERGENT, "The versions of trial " + trialId
                        + " did not decide the sealed decision " + sealedPackageId + " differently"));
        SealedEvidencePackage sealed = sealed(pair.sealedPackageId(), "The decision of package " + sealedPackageId);
        PromptQualityCases.Kept kept = cases.promote(trial.scope(), trial.prompt(), sealed, null, null, expectation,
                grade, actor);
        return new Promoted(kept, sealed.getPackageId(), pair.observationId(), null);
    }

    private PromptVersionTrials.Trial trial(long trialId) {
        PromptVersionTrials runner = trials.get();
        if (runner == null) {
            throw new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.NOT_FOUND,
                    "The trials of prompt versions are not in this application");
        }
        return runner.find(trialId).orElseThrow(() -> new PromptQualityCases.RefusedException(
                PromptQualityCases.Refusal.NOT_FOUND, "There is no trial " + trialId));
    }

    /** The sealed package, refused as not sealed when it is missing or its seal did not hold. */
    private SealedEvidencePackage sealed(@Nullable String packageId, String what) {
        SealedEvidencePackage sealed = packageId != null ? packages.findByPackageId(packageId).orElse(null) : null;
        if (sealed == null || !sealed.hasSealedState()) {
            throw new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.NOT_SEALED, what
                    + " is not sealed: there is no input of it to make a case of; its evaluation alone can be kept");
        }
        return sealed;
    }
}
