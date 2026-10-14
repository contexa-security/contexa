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

/** Where a fact of the v20 prompt comes from, as the prompt states it. */
public enum PromptSourceGrade {

    /** Stated by the host: business providers, bridge stamps, official request fields, resource descriptors. */
    HOST("host"),
    /** Learned by Contexa from allowed requests: baseline, work profile, past records. */
    LEARNED("learned"),
    /** Computed by the core from the request and the records. */
    COMPUTED("computed"),
    /** Estimated by a fallback rule because no explicit value exists. */
    INFERRED("inferred"),
    /** Text anyone can write. */
    UNTRUSTED("untrusted");

    private final String word;

    PromptSourceGrade(String word) {
        this.word = word;
    }

    /** The word the prompt writes for the grade. */
    public String word() {
        return word;
    }
}
