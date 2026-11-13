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
package io.contexa.contexaiam.admin.promptquality.governance;

import java.time.LocalDateTime;

/**
 * The two writes of the bundle rollback to tables JPA owns (persistence-ownership.yml: ctxa_prompt_governance_registry
 * and ctxa_prompt_governance_rollback_ledger are JPA_ONLY): the release state of a registered bundle, and the
 * readiness of a rollback target. Each write is visible to the reads that follow it.
 */
public interface PromptGovernanceStatusWriter {

    /** The release state of the bundle registered under the scope, prompt key and version. */
    void releaseStatus(String registryScope, String promptKey, String promptVersion, String status, LocalDateTime at);

    /** The readiness of the rollback ledger row. */
    void rollbackReadiness(long rollbackId, String readiness, LocalDateTime at);
}
