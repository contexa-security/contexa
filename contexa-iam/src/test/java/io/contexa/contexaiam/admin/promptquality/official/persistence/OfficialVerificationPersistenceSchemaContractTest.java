/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 */
package io.contexa.contexaiam.admin.promptquality.official.persistence;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationPersistenceSchemaContractTest {

    @Test
    void runBatchOwnsTenantAndRepairsExistingRowsFromSealedEvidence() throws IOException {
        String schema;
        try (InputStream input = getClass().getResourceAsStream("/db/schema.sql")) {
            assertThat(input).isNotNull();
            schema = new String(input.readAllBytes(), StandardCharsets.UTF_8)
                    .replaceAll("\\s+", " ");
        }

        assertThat(schema)
                .contains("package_id VARCHAR(256) NOT NULL, tenant_id VARCHAR(120) NOT NULL,")
                .contains("ALTER TABLE official_verification_run_batch ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(120);")
                .contains("UPDATE official_verification_run_batch batch SET tenant_id = sealed.tenant_id FROM sealed_evidence_package sealed WHERE batch.package_id = sealed.package_id AND batch.tenant_id IS NULL;")
                .contains("ON official_verification_run_batch(tenant_id, package_id, created_at DESC);")
                .contains("ALTER TABLE official_verification_execution_lock ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(120);")
                .contains("UPDATE official_verification_execution_lock execution SET tenant_id = sealed.tenant_id FROM sealed_evidence_package sealed WHERE execution.package_id = sealed.package_id AND execution.tenant_id IS NULL;")
                .contains("ALTER TABLE official_verification_execution_state_history ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(120);")
                .contains("UPDATE official_verification_execution_state_history history SET tenant_id = sealed.tenant_id FROM sealed_evidence_package sealed WHERE history.package_id = sealed.package_id AND history.tenant_id IS NULL;")
                .contains("ALTER TABLE official_verification_metric_execution_ledger ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(120);")
                .contains("UPDATE official_verification_metric_execution_ledger metric SET tenant_id = sealed.tenant_id FROM sealed_evidence_package sealed WHERE metric.package_id = sealed.package_id AND metric.tenant_id IS NULL;");
    }

    @Test
    void normalizedCheckLedgerPreservesFourEvaluationStatesWithoutInferringLegacyPass() throws IOException {
        String schema;
        try (InputStream input = getClass().getResourceAsStream("/db/schema.sql")) {
            assertThat(input).isNotNull();
            schema = new String(input.readAllBytes(), StandardCharsets.UTF_8)
                    .replaceAll("\\s+", " ");
        }

        assertThat(schema)
                .contains("ADD COLUMN IF NOT EXISTS evaluation_state VARCHAR(32);")
                .contains("'PASS', 'FAIL', 'NOT_APPLICABLE', 'NOT_EVALUATED'")
                .contains("CROSS JOIN LATERAL jsonb_array_elements")
                .contains("AND target.evaluation_state IS NULL;");
    }

    @Test
    void purposeLedgersRestoreCustomerVisibilityOnlyFromRawCheckEvidence() throws IOException {
        String schema;
        try (InputStream input = getClass().getResourceAsStream("/db/schema.sql")) {
            assertThat(input).isNotNull();
            schema = new String(input.readAllBytes(), StandardCharsets.UTF_8)
                    .replaceAll("\\s+", " ");
        }

        assertThat(schema)
                .contains("UPDATE official_metric_input_readiness_ledger target SET customer_visible = source.customer_visible")
                .contains("UPDATE official_metric_purpose_evaluation_ledger target SET customer_visible = source.customer_visible")
                .contains("UPDATE official_metric_purpose_evidence_ledger target SET customer_visible = source.customer_visible")
                .contains("check_json ? 'customerVisible'")
                .contains("target.customer_visible IS DISTINCT FROM source.customer_visible");
    }
}
