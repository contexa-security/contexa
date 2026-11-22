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
    String CANARY_STARTED = "PROMPT_VERSION_CANARY_STARTED";
    String CANARY_STOPPED = "PROMPT_VERSION_CANARY_STOPPED";
    String SHADOW_STARTED = "PROMPT_VERSION_SHADOW_STARTED";
    String SHADOW_STOPPED = "PROMPT_VERSION_SHADOW_STOPPED";
    String EMERGENCY_ROLLBACK = "PROMPT_VERSION_EMERGENCY_ROLLBACK";
    String ROLLBACK_APPROVED = "PROMPT_VERSION_ROLLBACK_APPROVED";
    String TRIAL_STARTED = "PROMPT_VERSION_TRIAL_STARTED";
    String TRIAL_CANCELLED = "PROMPT_VERSION_TRIAL_CANCELLED";
    /*
     * Quality plan 3.9: what is done to the labelled cases and their published sets. They name a case or a set, not a
     * version, so their names do not start like the version actions the history of a version reads: the version is
     * the case's key or the set's version.
     */
    String CASE_SUBMITTED = "PROMPT_QUALITY_CASE_SUBMITTED";
    String CASE_ANSWER_CHANGED = "PROMPT_QUALITY_CASE_ANSWER_CHANGED";
    String CASE_CONFIRMED = "PROMPT_QUALITY_CASE_CONFIRMED";
    String CASE_SET_PUBLISHED = "PROMPT_QUALITY_CASE_SET_PUBLISHED";

    /** Who the product's versions are registered by at start (plan 3.3): the product, no person. */
    String PRODUCT_ACTOR = "contexa";
    /** The start of who a version registered from a node's document folder is made by: the folder an operator filled. */
    String FOLDER_ACTOR = "folder:";

    void record(String action, String scope, String prompt, String version, String actor, String detail);

    /** An audit that records nothing. */
    static PromptVersionAudit none() {
        return (action, scope, prompt, version, actor, detail) -> {
        };
    }
}
