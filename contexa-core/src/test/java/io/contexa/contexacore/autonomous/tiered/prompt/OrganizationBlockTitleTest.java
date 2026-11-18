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

import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K67 (plan 3.5): the title the checks before a save refuse for a block an organization adds is exactly the title the
 * drawing of a version saved before them quotes, so that only the engine's blocks read as such: a standard block's
 * title in any case, spacing or with qualifiers after it.
 */
class OrganizationBlockTitleTest {

    private static final List<String> STANDARD = List.of("Session", "SESSION", "  user   baseline ", "Request",
            "Records and comparisons", "Decision facts (ours)", "Past records", "Unknown", "Untrusted text",
            "Second pass", "session (notes)");
    private static final List<String> OWN = List.of("Finance closing", "Sessions", "Our session", "(Session)",
            "Session notes", "User baseline of finance", "=== Session ===", "Request: exports");

    @Test
    void aTitleIsAStandardBlocksExactlyWhenTheDrawingQuotesIt() {
        List<String> titles = new ArrayList<>(STANDARD);
        titles.addAll(OWN);
        for (String title : titles) {
            AssembledPrompt version = new PromptAssembler().apply(SecurityDecisionPromptDocument.product(),
                    new PromptVersionDocumentReader().read("""
                            prompt: cortex.security-decision
                            basedOn: v1.0
                            title: Finance
                            user:
                              - key: org-block
                                add-after: REQUEST
                                title: "%s"
                                text: The ledger is exported on the last day.
                            """.formatted(title)));
            String drawn = SecurityDecisionPromptDocument.organizationBlocks(version).get(PromptBlock.REQUEST).get(0);
            boolean quoted = drawn.startsWith("=== \"");

            assertThat(PromptBlock.isBlockTitle(title)).as(title).isEqualTo(quoted)
                    .isEqualTo(STANDARD.contains(title));
        }
        assertThat(PromptBlock.isBlockTitle(null)).isFalse();
        assertThat(PromptBlock.isBlockTitle("  ")).isFalse();
    }
}
