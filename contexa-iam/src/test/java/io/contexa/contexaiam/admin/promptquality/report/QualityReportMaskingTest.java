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
package io.contexa.contexaiam.admin.promptquality.report;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 3.2: the masking of a quality report names a person by a pseudonym of the report alone and scrubs the
 * free texts of the persons, e-mail addresses and IP addresses, without taking the words around them.
 */
class QualityReportMaskingTest {

    @Test
    void aPersonIsOnePseudonymInAReportAndAnotherInTheNext() {
        QualityReportMasking one = new QualityReportMasking(new SecureRandom());
        QualityReportMasking other = new QualityReportMasking(new SecureRandom());

        String first = one.subject("kim.subject");

        assertThat(first).startsWith(QualityReportMasking.SUBJECT_PREFIX).hasSize(
                QualityReportMasking.SUBJECT_PREFIX.length() + 16).doesNotContain("kim");
        assertThat(one.subject(" kim.subject ")).isEqualTo(first);
        assertThat(one.subject("lee.other")).isNotEqualTo(first);
        assertThat(other.subject("kim.subject")).isNotEqualTo(first);
        assertThat(one.subject(null)).isNull();
        assertThat(one.subject(" ")).isNull();
        assertThat(one.subjects()).isEqualTo(2);
    }

    @Test
    void theFreeTextsLoseThePersonsTheMailAndTheAddresses() {
        QualityReportMasking masking = new QualityReportMasking(new SecureRandom());
        masking.know(List.of("kim.subject", "u1001"));
        String kim = masking.subject("kim.subject");

        String text = masking.text("kim.subject asked from 203.0.113.77 and 2001:db8:85a3::8a2e:370:7334, mail"
                + " kim.private@example.com; u1001. Not kim.subjects, not xkim.subject, not u10011.");

        assertThat(text).isEqualTo(kim + " asked from [ip] and [ip], mail [email]; " + masking.subject("u1001")
                + ". Not kim.subjects, not xkim.subject, not u10011.");
        assertThat(masking.scrubbedTexts()).isEqualTo(1);
        assertThat(masking.subjects()).as("a known person is named once it is met").isEqualTo(2);
    }

    @Test
    void timesVersionsAndPlainWordsStayAsTheyAre() {
        QualityReportMasking masking = new QualityReportMasking(new SecureRandom());
        String text = "At 12:30:00 the version 2026.11.18-v1.0 went to v2.0 (measurement=MEASURED, 25.0%)";

        assertThat(masking.text(text)).isEqualTo(text);
        assertThat(masking.text(null)).isNull();
        assertThat(masking.scrubbedTexts()).isZero();
        assertThat(masking.text("x".repeat(QualityReportMasking.TEXT_LIMIT + 5)))
                .hasSize(QualityReportMasking.TEXT_LIMIT);
    }
}
