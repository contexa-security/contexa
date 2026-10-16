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

import java.util.List;
import java.util.Map;

/**
 * The user blocks of a dictionary prompt as drawn.
 *
 * @param text         the blocks, each under its header, separated by a blank line, lines ending with a line feed
 * @param slots        one slot per drawn line, carrying its dictionary entry
 * @param blocks       the blocks that were drawn, in order
 * @param unknownNames the entries the prompt does not know this time, in name order
 * @param unknownFacts the same facts as the UNKNOWN line names them, kind first: {@code not-integrated: ClientSignals},
 *                     {@code unavailable-now: PastRecord (not retrieved, TIMEOUT)} (W4-7)
 * @param factIds      the fact ID of each line a reason code may cite (every block with an ID prefix), by the line's
 *                     label, in block order (W3-13, P3 extra 12)
 */
public record PromptDictionaryRendering(String text, List<PromptSlot> slots, List<PromptBlock> blocks,
                                        List<String> unknownNames, List<String> unknownFacts,
                                        Map<String, String> factIds) {
}
