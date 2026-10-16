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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.decision.RelativeTime;
import io.contexa.contexacore.autonomous.context.prompt.PromptListItem;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** W5-4: a decision that did not allow reads as the dictionary's PastDeniedDecision line. */
class PastDeniedLinesTest {

    private static final LocalDateTime REQUEST = LocalDateTime.of(2026, 10, 14, 3, 17);

    @Test
    void aDeniedDecisionReadsAsTheDictionaryLine() {
        LocalDateTime at = LocalDateTime.of(2026, 10, 12, 3, 17);
        PastDeniedDecisions decisions = new PastDeniedDecisions(List.of(
                new PastDeniedDecisions.Entry(at, "EXPORT", "projectKey=GB-500", "CHALLENGE",
                        PastDeniedDecisions.NOT_VERIFIED),
                new PastDeniedDecisions.Entry(null, null, null, "BLOCK", PastDeniedDecisions.RELEASED_BY_ADMINISTRATOR)));

        List<PromptListItem> items = PastDeniedLines.items(decisions, REQUEST);

        assertThat(items).extracting(PromptListItem::text).containsExactly(
                "10-12 Mon 03:17 (" + RelativeTime.of(at, REQUEST) + ") EXPORT projectKey=GB-500 -> CHALLENGE (not verified)",
                "time not recorded UNKNOWN no-target -> BLOCK (released by an administrator)");
        assertThat(items).extracting(PromptListItem::text)
                .allMatch(text -> text.matches(".+ [A-Z]+ \\S+ -> [A-Z]+ \\(.+\\)"));
        assertThat(PastDeniedLines.items(new PastDeniedDecisions(List.of()), REQUEST)).isEmpty();
    }
}
