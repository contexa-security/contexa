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

import java.sql.Timestamp;
import java.time.LocalDateTime;

import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The rollback's two state writes on the test schema of these tests, which has no JPA context: the same columns the
 * application's {@link JpaPromptGovernanceStatusWriter} sets through the repositories.
 */
final class JdbcTestStatusWriter implements PromptGovernanceStatusWriter {

    private final JdbcTemplate jdbc;

    JdbcTestStatusWriter(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void releaseStatus(String registryScope, String promptKey, String promptVersion, String status,
                              LocalDateTime at) {
        jdbc.update("update ctxa_prompt_governance_registry set release_status = ?, updated_at = ? "
                        + "where registry_scope = ? and prompt_key = ? and prompt_version = ?",
                status, Timestamp.valueOf(at), registryScope, promptKey, promptVersion);
    }

    @Override
    public void rollbackReadiness(long rollbackId, String readiness, LocalDateTime at) {
        jdbc.update("update ctxa_prompt_governance_rollback_ledger set rollback_readiness_state = ?, updated_at = ? "
                + "where id = ?", readiness, Timestamp.valueOf(at), rollbackId);
    }
}
