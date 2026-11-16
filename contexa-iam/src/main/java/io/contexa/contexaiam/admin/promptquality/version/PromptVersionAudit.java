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
package io.contexa.contexaiam.admin.promptquality.version;

/**
 * Where what was done to a version is recorded (plan 3.7): made, hidden, imported, registered from the folder, used for
 * decisions and the other label moves. The audit log of the console writes it; a test may count it.
 */
@FunctionalInterface
public interface PromptVersionAudit {

    String CREATED = "PROMPT_VERSION_CREATED";
    String HIDDEN = "PROMPT_VERSION_HIDDEN";
    String IMPORTED = "PROMPT_VERSION_IMPORTED";
    String FOLDER_REGISTERED = "PROMPT_VERSION_FOLDER_REGISTERED";
    String USED_FOR_DECISIONS = "PROMPT_VERSION_USED_FOR_DECISIONS";

    void record(String action, String scope, String prompt, String version, String actor, String detail);

    /** An audit that records nothing. */
    static PromptVersionAudit none() {
        return (action, scope, prompt, version, actor, detail) -> {
        };
    }
}
