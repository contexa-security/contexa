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

/**
 * Quality plan 9 (K161): the canonical context a replay fixed for its event was not there when its prompt was drawn
 * (the contexts a replay fixes are kept for a while and up to a number). The prompt of a replay is not drawn with the
 * context the provider resolves now instead: that would be another decision's inputs under the sealed decision's name.
 */
public class SealedReplayContextMissingException extends IllegalStateException {

    public SealedReplayContextMissingException(String replayEventId) {
        super("The sealed canonical context of replay " + replayEventId + " is no longer kept, so its prompt is not drawn");
    }
}
