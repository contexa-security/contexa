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
package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.testsupport.PromptQualityTestResolvers;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** PR-74: the run detail's evidence tells a package's real state too, not whether a hash is written down. */
class OfficialRunLightweightEvidenceReaderIntegrityTest {

    private static final String PACKAGE = "pkg-1";

    private final JdbcOperations jdbc = mock(JdbcOperations.class);
    private final SealedEvidencePackageQueryService packages = mock(SealedEvidencePackageQueryService.class);
    private final RuntimeEvidencePromptConsistencyGate gate = mock(RuntimeEvidencePromptConsistencyGate.class);
    private final OfficialRunLightweightEvidenceReader reader = new OfficialRunLightweightEvidenceReader(jdbc,
            new ObjectMapper(), gate, mock(PromptQualityRuntimeEvidenceService.class), packages,
            PromptQualityTestResolvers.koreanBundle());

    @Test
    void anIntactPackageIsValid() throws Exception {
        rowWith(true, "SEALED");
        storedPackageIsIntact(true);

        assertThat(reader.findDetail(PACKAGE).summary().integrityValid()).isTrue();
    }

    @Test
    void aChangedPackageIsInvalid() throws Exception {
        rowWith(true, "SEALED");
        storedPackageIsIntact(false);

        RuntimeEvidencePackageDetail detail = reader.findDetail(PACKAGE);

        assertThat(detail.summary().integrityValid()).isFalse();
        assertThat(detail.summary().state()).isEqualTo("INTEGRITY_WARNING");
        assertThat(detail.qualityWarnings()).isNotEmpty();
    }

    @Test
    void aSealThatFailedIsInvalidWithoutReadingThePackageAgain() throws Exception {
        rowWith(true, "FAILED");

        assertThat(reader.findDetail(PACKAGE).summary().integrityValid()).isFalse();
        verify(packages, never()).findByPackageId(anyString());
        verify(packages, never()).verifyIntegrity(any());
    }

    private void storedPackageIsIntact(boolean intact) {
        when(packages.verifyIntegrity(any())).thenReturn(intact);
    }

    @SuppressWarnings("unchecked")
    private void rowWith(boolean sealed, String sealState) throws SQLException {
        when(gate.evaluate(any())).thenReturn(RuntimeEvidencePromptConsistencyResult.empty());
        when(packages.findByPackageId(PACKAGE)).thenReturn(Optional.of(new SealedEvidencePackage()));
        when(jdbc.queryForObject(anyString(), any(RowMapper.class), any(Object[].class))).thenAnswer(call -> {
            RowMapper<SealedEvidencePackage> mapper = call.getArgument(1);
            ResultSet row = mock(ResultSet.class);
            when(row.getString("package_id")).thenReturn(PACKAGE);
            when(row.getString("package_hash")).thenReturn("hash");
            when(row.getString("seal_state")).thenReturn(sealState);
            when(row.getBoolean("sealed")).thenReturn(sealed);
            when(row.getInt("schema_version")).thenReturn(3);
            return mapper.mapRow(row, 0);
        });
    }
}
