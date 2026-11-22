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

import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseClass;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseKind;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseRationale;
import org.springframework.lang.Nullable;

import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Quality plan 3.6: the right answer an administrator sets when a decision of the operation is made a case, as the
 * input window of "add as a case" sends it from the sealed evidence, the trials and the decision detail: the actions
 * that are right, the one preferred among them, what the decision is and who acts, why, and the case's grade. The
 * reason is kept in the language of the administrator who wrote it.
 *
 * @param preferredAction the preferred action among the right ones, or none
 * @param grade           the case's grade, ordinary when none is given
 */
public record QualityCaseAnswerForm(@Nullable List<String> allowedActions, @Nullable String preferredAction,
                                    @Nullable String classification, @Nullable String kind,
                                    @Nullable String rationale, @Nullable String grade) {

    /**
     * The answer as a case's expectation.
     *
     * @param locale the language the reason is written in
     * @throws IllegalArgumentException when an action, the classification or the kind is unknown, no action is right,
     *                                  the preferred action is not a right one, or no reason is given
     */
    public QualityCaseExpectation expectation(@Nullable Locale locale) {
        Set<QualityAction> allowed = EnumSet.noneOf(QualityAction.class);
        for (String name : allowedActions != null ? allowedActions : List.<String>of()) {
            QualityAction action = QualityAction.parse(name);
            if (action == null) {
                throw new IllegalArgumentException("Unknown action " + name);
            }
            allowed.add(action);
        }
        QualityAction preferred = null;
        if (preferredAction != null && !preferredAction.isBlank()) {
            preferred = QualityAction.parse(preferredAction);
            if (preferred == null) {
                throw new IllegalArgumentException("Unknown preferred action " + preferredAction);
            }
        }
        boolean korean = locale != null && Locale.KOREAN.getLanguage().equals(locale.getLanguage());
        return new QualityCaseExpectation(allowed, preferred, QualityCaseClass.valueOf(upper(classification, "")),
                QualityCaseKind.valueOf(upper(kind, "")), new QualityCaseRationale(korean ? rationale : null,
                korean ? null : rationale), List.of());
    }

    /**
     * The case's grade.
     *
     * @throws IllegalArgumentException when the grade is unknown
     */
    public QualityCaseGrade caseGrade() {
        return QualityCaseGrade.valueOf(upper(grade, QualityCaseGrade.ORDINARY.name()));
    }

    private static String upper(@Nullable String value, String otherwise) {
        return value == null || value.isBlank() ? otherwise : value.trim().toUpperCase(Locale.ROOT);
    }
}
