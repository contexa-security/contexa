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

import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCasePromotionViews.Promotion;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Evaluation;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Locale;
import java.util.function.Supplier;

/**
 * Quality plan 3.6: in the decision detail of the Zero Trust console (a decision of the review queue included), an
 * administrator evaluates a decision and makes it a labelled case with the right answer in one step, both or neither.
 * A decision is made a case only from its seal: one that is not sealed is refused as such, its evaluation then kept
 * through the evaluation alone. A case of a decision the second analysis decided is marked and counted apart. The call
 * is an administrator's POST under the console's JSON, which the console's CSRF protection covers, as the evaluation.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class QualityCaseDecisionController {

    /** The decisions of the Zero Trust console, under its JSON. */
    static final String DECISIONS = "/contexa/admin/api/zero-trust/decisions";

    private final Supplier<QualityCasePromotions> promotions;

    /** @param promotions what makes a decision a case; a supplier of null when the cases are not here */
    public QualityCaseDecisionController(Supplier<QualityCasePromotions> promotions) {
        this.promotions = promotions != null ? promotions : () -> null;
    }

    /** The evaluation of a decision and the answer of the case it is made in the same step. */
    public record DecisionCase(@Nullable Evaluation evaluation, @Nullable QualityCaseAnswerForm answer) {
    }

    /**
     * Evaluates the decision and makes it a case with the answer set, both or neither: the case's scope is the
     * platform's, as the decision records read every tenant's decisions.
     */
    @ResponseBody
    @PostMapping(DECISIONS + "/{observationId}/case")
    public ResponseEntity<?> decisionCase(@PathVariable String observationId, @RequestBody DecisionCase body,
                                          Locale locale, Authentication authentication) {
        QualityCasePromotionController.requireAdmin(authentication);
        QualityCasePromotions promoting = promotions.get();
        if (promoting == null) {
            return QualityCasePromotionController.unavailable();
        }
        if (body == null || body.evaluation() == null || body.answer() == null) {
            return QualityCasePromotionController.invalid("An evaluation and an answer are required");
        }
        QualityCaseExpectation expectation;
        QualityCaseGrade grade;
        try {
            expectation = body.answer().expectation(locale);
            grade = body.answer().caseGrade();
        }
        catch (IllegalArgumentException | NullPointerException unreadable) {
            return QualityCasePromotionController.invalid(unreadable.getMessage());
        }
        try {
            return ResponseEntity.ok(Promotion.of(promoting.fromEvaluation(null, observationId, body.evaluation(),
                    expectation, grade, authentication.getName())));
        }
        catch (PromptQualityCases.RefusedException refusal) {
            return QualityCasePromotionViews.refused(refusal);
        }
        catch (IllegalArgumentException invalid) {
            return QualityCasePromotionController.invalid(invalid.getMessage());
        }
    }
}
