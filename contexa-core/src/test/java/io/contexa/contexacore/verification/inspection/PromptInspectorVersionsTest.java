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
package io.contexa.contexacore.verification.inspection;

import org.junit.jupiter.api.Test;

import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/** R1b-7: every raise of the inspector version is kept once, in order, with its reason, and the last is the one run. */
class PromptInspectorVersionsTest {

    @Test
    void everyRaiseIsKeptOnceInOrderWithItsReason() {
        assertThat(PromptInspectorVersions.ALL).extracting(PromptInspectorVersions.Version::number)
                .containsExactlyElementsOf(IntStream.rangeClosed(1, PromptInspectorVersions.ALL.size()).boxed().toList());
        assertThat(PromptInspectorVersions.ALL).hasSizeGreaterThanOrEqualTo(12)
                .allSatisfy(version -> assertThat(version.reason()).isNotBlank());
        assertThat(PromptInspectorVersions.ALL.get(4).reason()).contains("P3 extra 12");
    }

    @Test
    void theInspectorRunsTheLastVersion() {
        assertThat(PromptInspector.INSPECTOR_VERSION).isEqualTo(PromptInspectorVersions.current().name());
        assertThat(PromptInspectorVersions.current().number()).isEqualTo(PromptInspectorVersions.ALL.size());
    }

    /** N-SRC-2 lands in version 20 with N-INJ-3, N-INS-2 and N-INS-3 (one P8 build), not in a version of its own. */
    @Test
    void theSourceRecordsAHostDoesNotKeepAreNamedInVersionTwenty() {
        PromptInspectorVersions.Version twenty = PromptInspectorVersions.ALL.get(19);
        assertThat(twenty.number()).isEqualTo(20);
        assertThat(twenty.reason()).contains("(N-INJ-3)").contains("(N-INS-3)").contains("(N-SRC-2)");
    }

    /** N-INS-4, the first change after P8, is version 21. */
    @Test
    void thePastRecordsReasonsAreComparedFromVersionTwentyOne() {
        PromptInspectorVersions.Version twentyOne = PromptInspectorVersions.ALL.get(20);
        assertThat(twentyOne.number()).isEqualTo(21);
        assertThat(twentyOne.reason()).contains("(N-INS-4)");
    }

    /** N-INJ-4 is version 22. */
    @Test
    void aCategoryThatIsNotATokenIsComparedFromVersionTwentyTwo() {
        PromptInspectorVersions.Version twentyTwo = PromptInspectorVersions.ALL.get(21);
        assertThat(twentyTwo.number()).isEqualTo(22);
        assertThat(twentyTwo.reason()).contains("(N-INJ-4)");
    }

    /** V-6 of the v21 plan: the v21 packages are read from version 23. */
    @Test
    void theV21PackagesAreReadFromVersionTwentyThree() {
        PromptInspectorVersions.Version twentyThree = PromptInspectorVersions.ALL.get(22);
        assertThat(twentyThree.number()).isEqualTo(23);
        assertThat(twentyThree.reason()).contains("v21").contains("(V-6 of the v21 plan)");
    }

    /** Finding 7 of the v21 plan: the target scope line of a v21 package is compared from version 24. */
    @Test
    void theTargetScopeIsComparedFromVersionTwentyFour() {
        PromptInspectorVersions.Version twentyFour = PromptInspectorVersions.ALL.get(23);
        assertThat(twentyFour.number()).isEqualTo(24);
        assertThat(twentyFour.reason()).contains("(finding 7 of the v21 plan)");
    }

    /** Finding 12 of the v21 plan: a v21 reason code citing the past records' counted fact is checked from 25. */
    @Test
    void theCountedFactCitationIsCheckedFromVersionTwentyFive() {
        PromptInspectorVersions.Version twentyFive = PromptInspectorVersions.ALL.get(24);
        assertThat(twentyFive.number()).isEqualTo(25);
        assertThat(twentyFive.reason()).contains("(finding 12 of the v21 plan)");
    }

    /** CQ-1: the argument origin line and the tool output sentence of a v21 package are compared from version 26. */
    @Test
    void theArgumentOriginsAreComparedFromVersionTwentySix() {
        PromptInspectorVersions.Version twentySix = PromptInspectorVersions.ALL.get(25);
        assertThat(twentySix.number()).isEqualTo(26);
        assertThat(twentySix.reason()).contains("argument origin line").contains("(CQ-1)");
    }

    /** BR-C6: the learned field and the arguments field of a v21 past record line are compared from version 27. */
    @Test
    void theLearnedFieldOfAPastRecordLineIsComparedFromVersionTwentySeven() {
        PromptInspectorVersions.Version twentySeven = PromptInspectorVersions.ALL.get(26);
        assertThat(twentySeven.number()).isEqualTo(27);
        assertThat(twentySeven.reason()).contains("learned field").contains("(BR-C6)");
    }

    /** Q-21: the seal check points at a missing signature and at a break in the chain from version 28. */
    @Test
    void aMissingSignatureAndABrokenLinkAreFoundFromVersionTwentyEight() {
        PromptInspectorVersions.Version twentyEight = PromptInspectorVersions.ALL.get(27);
        assertThat(twentyEight.number()).isEqualTo(28);
        assertThat(twentyEight.reason()).contains("signature").contains("(Q-21)");
    }

    /** A key never held and a lowered package with any text as its signature are found from version 29. */
    @Test
    void aKeyNeverHeldIsFoundFromVersionTwentyNine() {
        PromptInspectorVersions.Version twentyNine = PromptInspectorVersions.ALL.get(28);
        assertThat(twentyNine.number()).isEqualTo(29);
        assertThat(twentyNine.reason()).contains("never held").contains("as its signature");
    }

    /** N-OUT-3 lands in version 22 with N-INJ-4 (one build after P8), not in a version of its own. */
    @Test
    void theOutputRetriesAreComparedFromVersionTwentyTwo() {
        PromptInspectorVersions.Version twentyTwo = PromptInspectorVersions.ALL.get(21);
        assertThat(twentyTwo.number()).isEqualTo(22);
        assertThat(twentyTwo.reason()).contains("(N-INJ-4)").contains("(N-OUT-3)");
    }
}
