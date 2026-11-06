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
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceSearchCriteria;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.state.DefaultPromptQualityStateCatalog;
import io.contexa.contexaiam.testsupport.PromptQualityTestResolvers;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PR-74: what the console says of a package's integrity is the package's real state. The list and the detail read a
 * lightweight row, which leaves out columns the hash covers, so the answer comes from the package as stored.
 */
class RuntimeEvidenceIntegrityTest {

    private static final String KEY = Base64.getEncoder().encodeToString("k1-0123456789abcdef0123456789abcd".getBytes());

    private final SealedEvidencePackageIntegrity integrity =
            new SealedEvidencePackageIntegrity(HmacEvidenceSigner.of(Map.of("k1", KEY), null));
    private final SealedEvidencePackageRepository repository = mock(SealedEvidencePackageRepository.class);
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final SealedEvidencePackageQueryService queries = new DefaultSealedEvidencePackageQueryService(
            new SealedEvidencePackageLookupService(repository, integrity), jdbc);
    private final DefaultPromptQualityRuntimeEvidenceService evidence = new DefaultPromptQualityRuntimeEvidenceService(
            queries, new ObjectMapper(), PromptQualityTestResolvers.koreanBundle(),
            mock(RuntimeEvidencePromptConsistencyGate.class), new DefaultPromptQualityStateCatalog(),
            mock(PromptQualityProcessRunService.class));

    @Test
    void anIntactPackageIsValidInTheListAndTheDetail() throws Exception {
        store(sealed("pkg-1"));

        assertThat(listed("pkg-1").integrityValid()).isTrue();
        assertThat(detail("pkg-1").summary().integrityValid()).isTrue();
        assertThat(detail("pkg-1").qualityWarnings()).noneMatch(warning -> warning.contains("무결성"));
    }

    @Test
    void aDecisionChangedAfterTheSealIsInvalidInTheListAndTheDetail() throws Exception {
        SealedEvidencePackage changed = sealed("pkg-1");
        changed.setDecisionJson("{\"action\":\"BLOCK\"}");
        store(changed);

        assertThat(listed("pkg-1").integrityValid()).isFalse();
        assertThat(detail("pkg-1").summary().integrityValid()).isFalse();
        assertThat(detail("pkg-1").qualityWarnings()).isNotEmpty();
    }

    /** The lightweight row does not hold this column: only the stored package can tell. */
    @Test
    void aChangeInAColumnTheLightweightRowLeavesOutIsSeen() throws Exception {
        SealedEvidencePackage changed = sealed("pkg-1");
        changed.setCanonicalContextJson("{\"actor\":{\"userId\":\"someone-else\"}}");
        store(changed);

        assertThat(listed("pkg-1").integrityValid()).isFalse();
        assertThat(detail("pkg-1").summary().integrityValid()).isFalse();
    }

    @Test
    void aHashComputedAgainWithoutTheKeyIsInvalid() throws Exception {
        SealedEvidencePackage changed = sealed("pkg-1");
        changed.setDecisionJson("{\"action\":\"BLOCK\"}");
        changed.setPackageHash(integrity.computeHash(changed));
        store(changed);

        assertThat(listed("pkg-1").integrityValid()).isFalse();
        assertThat(detail("pkg-1").summary().integrityValid()).isFalse();
    }

    @Test
    void eachRowOfAPageAnswersForItself() throws Exception {
        SealedEvidencePackage intact = sealed("pkg-1");
        SealedEvidencePackage changed = sealed("pkg-2");
        changed.setUserPromptText("changed after the seal");
        store(intact);
        store(changed);
        rowsOfAPage(intact, changed);

        List<RuntimeEvidencePackageSummary> page = evidence.search(new RuntimeEvidenceSearchCriteria(
                null, null, null, null, null, null, null, null, 0, 20));

        assertThat(page).extracting(RuntimeEvidencePackageSummary::packageId, RuntimeEvidencePackageSummary::integrityValid)
                .containsExactly(tuple("pkg-1", true), tuple("pkg-2", false));
    }

    @Test
    void aPackageNeverSealedIsNotValidAndItsRowIsNotReadAgain() throws Exception {
        SealedEvidencePackage unsealed = sealed("pkg-1");
        unsealed.setSealed(false);
        store(unsealed);

        assertThat(listed("pkg-1").integrityValid()).isFalse();
        verify(repository, never()).findByPackageId(anyString());
    }

    @Test
    void aPackageDeletedSinceItWasListedIsNotValid() throws Exception {
        store(sealed("pkg-1"));
        when(repository.findByPackageId("pkg-1")).thenReturn(Optional.empty());

        assertThat(listed("pkg-1").integrityValid()).isFalse();
    }

    private RuntimeEvidencePackageSummary listed(String packageId) {
        List<RuntimeEvidencePackageSummary> found = evidence.search(new RuntimeEvidenceSearchCriteria(
                packageId, null, null, null, null, null, null, null, 0, 20));
        assertThat(found).hasSize(1);
        return found.get(0);
    }

    private RuntimeEvidencePackageDetail detail(String packageId) {
        return evidence.findDetail(packageId);
    }

    private SealedEvidencePackage sealed(String packageId) {
        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId(packageId)
                .correlationId("req-" + packageId)
                .tenantId("tenant-a")
                .userId("alice")
                .capturedAt(Instant.parse("2026-11-05T01:02:03.456789Z").truncatedTo(ChronoUnit.MICROS))
                .requestFactsJson("{\"requestPath\":\"/orders\",\"httpMethod\":\"GET\"}")
                .canonicalContextJson("{\"actor\":{\"userId\":\"alice\"}}")
                .authStateJson("{}")
                .baselineSnapshotJson("{}")
                .ragResultsJson("{}")
                .systemPromptText("system")
                .userPromptText("user")
                .systemPromptHash("system-hash")
                .userPromptHash("user-hash")
                .rawSystemPrompt("raw system")
                .rawUserPrompt("raw user")
                .rawSystemPromptHash("raw-system-hash")
                .rawUserPromptHash("raw-user-hash")
                .decisionJson("{\"action\":\"ALLOW\"}")
                .sealState("SEALED")
                .schemaVersion(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION)
                .sealed(true)
                .build();
        integrity.seal(pkg, "previous-hash");
        pkg.setId(7L);
        return pkg;
    }

    /** The package as the store holds it, whole by its repository and as a lightweight row through the query. */
    private void store(SealedEvidencePackage pkg) throws SQLException {
        when(repository.findByPackageId(pkg.getPackageId())).thenReturn(Optional.of(pkg));
        when(jdbc.query(contains("where package_id = ?"), any(RowMapper.class), any(Object[].class))).thenAnswer(call -> {
            RowMapper<SealedEvidencePackage> mapper = call.getArgument(1);
            return List.of(mapper.mapRow(row(pkg), 0));
        });
    }

    private void rowsOfAPage(SealedEvidencePackage... packages) throws SQLException {
        when(jdbc.query(contains("order by captured_at desc"), any(RowMapper.class), any(Object[].class))).thenAnswer(call -> {
            RowMapper<SealedEvidencePackage> mapper = call.getArgument(1);
            List<SealedEvidencePackage> rows = new ArrayList<>();
            for (SealedEvidencePackage pkg : packages) {
                rows.add(mapper.mapRow(row(pkg), 0));
            }
            return rows;
        });
    }

    /** The columns the lightweight select reads; the columns it leaves out are not offered. */
    private static ResultSet row(SealedEvidencePackage pkg) throws SQLException {
        Map<String, String> columns = new HashMap<>();
        columns.put("package_id", pkg.getPackageId());
        columns.put("correlation_id", pkg.getCorrelationId());
        columns.put("tenant_id", pkg.getTenantId());
        columns.put("user_id", pkg.getUserId());
        columns.put("request_facts_json", pkg.getRequestFactsJson());
        columns.put("auth_state_json", pkg.getAuthStateJson());
        columns.put("baseline_snapshot_json", pkg.getBaselineSnapshotJson());
        columns.put("rag_results_json", pkg.getRagResultsJson());
        columns.put("system_prompt_text", pkg.getSystemPromptText());
        columns.put("user_prompt_text", pkg.getUserPromptText());
        columns.put("system_prompt_hash", pkg.getSystemPromptHash());
        columns.put("user_prompt_hash", pkg.getUserPromptHash());
        columns.put("raw_system_prompt_hash", pkg.getRawSystemPromptHash());
        columns.put("raw_user_prompt_hash", pkg.getRawUserPromptHash());
        columns.put("seal_state", pkg.getSealState());
        columns.put("decision_json", pkg.getDecisionJson());
        columns.put("package_hash", pkg.getPackageHash());
        ResultSet row = mock(ResultSet.class);
        when(row.getString(anyString())).thenAnswer(call -> columns.get(call.<String>getArgument(0)));
        when(row.getTimestamp("captured_at")).thenReturn(Timestamp.from(pkg.getCapturedAt()));
        when(row.getInt("schema_version")).thenReturn(pkg.getSchemaVersion());
        when(row.getBoolean("sealed")).thenReturn(pkg.isSealed());
        return row;
    }
}
