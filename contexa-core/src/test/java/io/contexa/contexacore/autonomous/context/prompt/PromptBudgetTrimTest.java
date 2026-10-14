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
package io.contexa.contexacore.autonomous.context.prompt;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** W3-7: a prompt over its budget takes entries out by dictionary priority, from the back, never a required one. */
class PromptBudgetTrimTest {

    private static final List<PromptDictionaryEntry> DICTIONARY = SecurityDecisionPromptDictionary.ENTRIES;

    @Test
    void supportingEntriesGoFirstThenHighValueOnesFromTheBackAndRequiredOnesNever() {
        List<PromptDictionaryEntry> order = PromptBudgetTrim.order(DICTIONARY, DICTIONARY);

        assertThat(order).extracting(PromptDictionaryEntry::name).startsWith("SupportingCases", "PeerReference",
                "NewlyKnown", "FirstPassVerdict", "UntrustedText{i}", "Unknown", "Coverage", "PastRecordsState",
                "PeerCohort", "Subject");
        assertThat(order).noneMatch(entry -> PromptDictionaryEntry.PRIORITY_REQUIRED.equals(entry.priority()));
        assertThat(order).hasSize((int) DICTIONARY.stream()
                .filter(entry -> !PromptDictionaryEntry.PRIORITY_REQUIRED.equals(entry.priority())).count());
    }

    @Test
    void takingOutStopsOnceThePromptFits() {
        List<PromptDictionaryEntry> order = PromptBudgetTrim.order(DICTIONARY, DICTIONARY);

        assertThat(PromptBudgetTrim.withhold(order, withheld -> withheld.size() < 2)).containsExactly(order.get(0), order.get(1));
        assertThat(PromptBudgetTrim.withhold(order, withheld -> false)).isEmpty();
        assertThat(PromptBudgetTrim.withhold(order, withheld -> true)).isEqualTo(order);
    }

    @Test
    void onlyTheDrawnEntriesAreTakenOut() {
        List<PromptDictionaryEntry> session = DICTIONARY.stream().filter(entry -> entry.block() == PromptBlock.SESSION).toList();

        assertThat(PromptBudgetTrim.order(DICTIONARY, session)).extracting(PromptDictionaryEntry::name)
                .containsExactly("RecentSensitiveAccess", "PasswordAge", "ConcurrentSessions", "RecentMfaElsewhere",
                        "SessionAge");
    }
}
