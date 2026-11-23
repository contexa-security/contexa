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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Locale;
import java.util.function.Supplier;

/**
 * Quality plan 3.6: in the result of a trial (a measurement on the latest sealed decisions), a sealed decision the two
 * versions decided differently is made a labelled case with the answer an administrator sets. A decision is made a case
 * only from its seal: one that is not sealed is refused as such. The case is a POST, which the console's CSRF
 * protection covers.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class QualityCasePromotionController {

    /** The trials of measure and compare, under the JSON of the screen. */
    static final String TRIALS = "/contexa/admin/api/prompt-quality/measure/trials";

    private final Supplier<QualityCasePromotions> promotions;

    /** @param promotions what makes a decision a case; a supplier of null when the cases are not here */
    public QualityCasePromotionController(Supplier<QualityCasePromotions> promotions) {
        this.promotions = promotions != null ? promotions : () -> null;
    }

    /** A sealed decision of a trial and the answer of its case. */
    public record TrialCase(@Nullable String packageId, @Nullable QualityCaseAnswerForm answer) {
    }

    /** The sealed decisions the two versions of the trial decided differently, the ones that can be made cases. */
    @ResponseBody
    @GetMapping(TRIALS + "/{trialId:\\d+}/divergent")
    public ResponseEntity<?> divergent(@PathVariable long trialId, Authentication authentication) {
        requireAdmin(authentication);
        QualityCasePromotions promoting = promotions.get();
        if (promoting == null) {
            return unavailable();
        }
        try {
            List<QualityCasePromotions.Divergent> divergent = promoting.divergent(trialId);
            return ResponseEntity.ok(divergent);
        }
        catch (PromptQualityCases.RefusedException refusal) {
            return QualityCasePromotionViews.refused(refusal);
        }
    }

    /** Makes a sealed decision the two versions of the trial decided differently a case of the trial's scope. */
    @ResponseBody
    @PostMapping(TRIALS + "/{trialId:\\d+}/cases")
    public ResponseEntity<?> trialCase(@PathVariable long trialId, @RequestBody TrialCase body, Locale locale,
                                       Authentication authentication) {
        requireAdmin(authentication);
        QualityCasePromotions promoting = promotions.get();
        if (promoting == null) {
            return unavailable();
        }
        if (body == null || body.packageId() == null || body.packageId().isBlank() || body.answer() == null) {
            return invalid("A sealed decision and its answer are required");
        }
        QualityCaseExpectation expectation;
        QualityCaseGrade grade;
        try {
            expectation = body.answer().expectation(locale);
            grade = body.answer().caseGrade();
        }
        catch (IllegalArgumentException | NullPointerException unreadable) {
            return invalid(unreadable.getMessage());
        }
        try {
            return ResponseEntity.ok(Promotion.of(promoting.fromTrial(trialId, body.packageId().trim(), expectation,
                    grade, authentication.getName())));
        }
        catch (PromptQualityCases.RefusedException refusal) {
            return QualityCasePromotionViews.refused(refusal);
        }
    }

    static ResponseEntity<?> invalid(@Nullable String message) {
        return QualityCasePromotionViews.refused(HttpStatus.BAD_REQUEST, PromptQualityCases.Refusal.INVALID.name(),
                message);
    }

    static ResponseEntity<?> unavailable() {
        return QualityCasePromotionViews.refused(HttpStatus.SERVICE_UNAVAILABLE, "UNAVAILABLE",
                "The labelled cases are not here");
    }

    static void requireAdmin(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        boolean admin = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("ROLE_ADMIN"::equals);
        if (!admin) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
    }
}
