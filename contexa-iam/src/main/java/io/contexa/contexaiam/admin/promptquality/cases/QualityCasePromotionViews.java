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

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;

/**
 * Quality plan 3.6: what the screens that make a decision of the operation a case (the sealed evidence, the trials, the
 * decision detail) answer: the case it became, or why it could not become one, with the status of the refusal.
 */
public final class QualityCasePromotionViews {

    private QualityCasePromotionViews() {
    }

    /**
     * The case a decision became.
     *
     * @param status         whether it waits for another administrator's confirmation
     * @param secondAnalysis whether the decision was decided by the second analysis, so the case is counted apart
     * @param evaluation     the kind of the evaluation kept with it, or null when none was
     */
    public record Promotion(String caseKey, String status, String sealedPackageId, @Nullable String observationId,
                            boolean secondAnalysis, @Nullable String evaluation) {

        public static Promotion of(QualityCasePromotions.Promoted promoted) {
            return new Promotion(promoted.kept().key(), promoted.kept().status(), promoted.sealedPackageId(),
                    promoted.observationId(), promoted.kept().secondAnalysis(),
                    promoted.evaluation() != null ? promoted.evaluation().kind() : null);
        }
    }

    /** Why a decision could not be made a case: the refusal of the cases (or INVALID, UNAVAILABLE) and its message. */
    public record Refused(String refusal, String message) {
    }

    /** A refusal of the cases as the answer of a screen's call. */
    public static ResponseEntity<Refused> refused(PromptQualityCases.RefusedException refusal) {
        HttpStatus status = switch (refusal.refusal()) {
            case NOT_FOUND -> HttpStatus.NOT_FOUND;
            case INVALID, PROMPT -> HttpStatus.BAD_REQUEST;
            default -> HttpStatus.CONFLICT;
        };
        return refused(status, refusal.refusal().name(), refusal.getMessage());
    }

    public static ResponseEntity<Refused> refused(HttpStatus status, String refusal, @Nullable String message) {
        return ResponseEntity.status(status).body(new Refused(refusal, message));
    }
}
