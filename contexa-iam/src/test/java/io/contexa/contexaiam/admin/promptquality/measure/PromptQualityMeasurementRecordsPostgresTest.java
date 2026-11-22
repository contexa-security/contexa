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
package io.contexa.contexaiam.admin.promptquality.measure;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptSections;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.evidence.JdbcSealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionStore;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.mockito.ArgumentCaptor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Quality plan 3.3: a measurement goes through the operator's replay of a decision given in memory and the engine's
 * replay service, the model stood in for by a pipeline that draws the prompt and answers, and leaves no record of a
 * decision: no decision observation, no sealed package, no outcome, and the baselines are neither learned nor read
 * as Contexa keeps them; the answers carry the prompts the template drew.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptQualityMeasurementRecordsPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String TENANT_SCOPE = "TENANT_A";
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false).findAndRegisterModules();
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    @BeforeAll
    static void aDatabaseWithTheSchema() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        try (Connection connection = database.dataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.setEscapeProcessing(false);
            statement.execute(schema);
        }
    }

    @AfterAll
    static void close() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    void aMeasurementLeavesNoRecordOfADecision() throws Exception {
        PromptVersionService versions = new PromptVersionService(() -> jdbc,
                SecurityDecisionPromptDocument.productReleases(), Map.of(), PromptVersionAudit.none(),
                Clock.systemUTC());
        versions.registerProducts(null);
        QualityCaseSet all = QualityCaseSetReader.contexaDefault();
        QualityCase normal = all.cases().stream().filter(item -> !item.shouldStop()).findFirst().orElseThrow();
        QualityCase threat = all.cases().stream().filter(QualityCase::shouldStop).findFirst().orElseThrow();
        QualityCaseSet two = new QualityCaseSet(all.name(), List.of(normal, threat));
        PromptQualityCases cases = new PromptQualityCases(() -> jdbc, MAPPER, false, PromptVersionAudit.none(),
                Clock.systemUTC(), null, () -> two);
        cases.publish(PromptVersionService.PLATFORM_SCOPE, PROMPT, "admin");

        TieredStrategyProperties properties = new TieredStrategyProperties();
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityDecisionPromptSections(new SecurityEventEnricher(), properties, event -> Optional.empty(),
                        new PromptContextComposer()));
        PromptVersionStore products = SecurityDecisionPromptDocument.productStore();
        template.setPromptVersionStore(new JdbcPromptVersionStore(versions, products::find));
        List<String> drawn = new CopyOnWriteArrayList<>();
        PipelineOrchestrator pipeline = new PipelineOrchestrator(List.of()) {
            @Override
            @SuppressWarnings("unchecked")
            public <T extends DomainContext, R extends AIResponse> Mono<R> execute(
                    AIRequest<T> request, PipelineConfiguration config, Class<R> responseType) {
                String userPrompt = template.generateUserPrompt(request, null);
                drawn.add(userPrompt);
                SecurityDecisionResponse response = new SecurityDecisionResponse();
                // The engine's pipeline gives back the prompts it drew when the request asks for them, as a replay does.
                if (Boolean.TRUE.equals(request.getParameter(PromptRuntimeTelemetrySupport.KEEP_DRAWN_PROMPTS,
                        Boolean.class))) {
                    response.withMetadata(PromptRuntimeTelemetrySupport.DRAWN_SYSTEM_PROMPT,
                            template.generateSystemPrompt(request, null));
                    response.withMetadata(PromptRuntimeTelemetrySupport.DRAWN_USER_PROMPT, userPrompt);
                }
                response.setAction("BLOCK");
                response.setReasoning("stand-in");
                return Mono.just((R) response);
            }
        };
        BaselineDataStore baselines = mock(BaselineDataStore.class);
        CentralAuditFacade audit = mock(CentralAuditFacade.class);
        SealedDecisionReplayService service = new SealedDecisionReplayService(template, pipeline,
                new BaselineLearningService(baselines, new SecurityZeroTrustProperties()), properties,
                StructuredOutputCapabilityRegistry.defaultRegistry(), () -> null, null, "OBSERVE",
                new CanonicalSecurityContextSerializer(MAPPER), MAPPER);
        SealedDecisionReplays replays = new SealedDecisionReplays(new JdbcSealedEvidencePackageRepository(jdbc),
                () -> service, baselines, audit, MAPPER, new SealedEvidencePackageIntegrity(),
                () -> new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> null));
        PromptQualityRunLine line = new PromptQualityRunLine();
        PromptQualityMeasurements measurements = new PromptQualityMeasurements(() -> jdbc, versions, cases,
                (actor, given, format, version, user, organization, scope, timeZone) -> replays.replayGiven(actor,
                        given, format, timeZone, new SealedDecisionReplays.ReplayRequest(version, null, user,
                                organization, true, scope)).result(),
                line, QualityMeasureLock.local(),
                () -> QualityModelSetting.settings(properties, null, new SecurityZeroTrustProperties()),
                () -> QualityModelSetting.closingRules(properties),
                new PromptQualityMeasurements.Settings(1, 1, 0, Duration.ZERO, 0, Duration.ofMillis(200)), MAPPER,
                Clock.systemUTC(), "server-a");
        try {
            long id = measurements.start(PromptVersionService.PLATFORM_SCOPE, PROMPT, 1, null, 1, "admin");
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
            while (!PromptQualityMeasurements.DONE.equals(measurements.find(id).orElseThrow().status())
                    && System.nanoTime() < until) {
                Thread.sleep(50);
            }
            PromptQualityMeasurements.Measure measure = measurements.find(id).orElseThrow();
            assertThat(measure.status()).isEqualTo(PromptQualityMeasurements.DONE);
            assertThat(measure.answered()).isEqualTo(2);
            assertThat(jdbc.queryForList("select outcome from ctxa_prompt_version_measure_answer where measure_id = ?",
                    String.class, id)).containsOnly(SealedDecisionReplayService.Outcome.ANSWERED.name());
            // The template drew each case's prompt from its input, and the answer names it by its hash.
            assertThat(drawn).hasSize(2).allMatch(prompt -> !prompt.isBlank());
            assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_measure_answer where"
                    + " measure_id = ? and user_prompt_hash is not null and system_prompt_hash is not null", Integer.class,
                    id)).isEqualTo(2);
            assertThat(jdbc.queryForList("select prompt_text from ctxa_prompt_version_measure_prompt p join"
                    + " ctxa_prompt_version_measure_answer a on a.user_prompt_hash = p.prompt_hash where a.measure_id = ?",
                    String.class, id)).containsExactlyInAnyOrderElementsOf(drawn);

            // Nothing of a decision is written, and the baselines are neither learned nor read as kept now.
            for (String table : List.of("ctxa_ai_security_decision_observation", "ctxa_sealed_evidence_package",
                    "ctxa_zt_decision_outcome")) {
                assertThat(jdbc.queryForObject("select count(*) from " + table, Integer.class)).as(table).isZero();
            }
            verifyNoInteractions(baselines);
            // The replay of each case is audited as the replay of a decision given in memory (out of plan P19).
            ArgumentCaptor<AuditRecord> records = ArgumentCaptor.forClass(AuditRecord.class);
            verify(audit, atLeastOnce()).recordAsync(records.capture());
            assertThat(records.getAllValues()).hasSize(2);
            assertThat(records.getAllValues()).allSatisfy(record ->
                    assertThat(record.getDetails()).containsEntry("given", true));

            // Quality plan 3.2 (P28): a measurement of another scope replays the version of that scope, which the
            // platform scope does not have; the engine draws its organization's block.
            versions.registerProducts(TENANT_SCOPE);
            versions.create(TENANT_SCOPE, """
                    prompt: cortex.security-decision
                    basedOn: v1.0
                    title: Tenant closing
                    user:
                      - key: tenant-closing
                        add-after: REQUEST
                        title: Tenant closing
                        text: |
                          The tenant's finance staff export the ledger on the last business day of a month.
                    """, PromptVersionRecord.SCREEN, null, "admin", null);
            assertThat(versions.find(PromptVersionService.PLATFORM_SCOPE, PROMPT, 2)).isEmpty();
            cases.publish(TENANT_SCOPE, PROMPT, "admin");
            long tenant = measurements.start(TENANT_SCOPE, PROMPT, 2, null, 1, "admin");
            long tenantUntil = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
            while (!PromptQualityMeasurements.DONE.equals(measurements.find(tenant).orElseThrow().status())
                    && System.nanoTime() < tenantUntil) {
                Thread.sleep(50);
            }
            assertThat(measurements.find(tenant).orElseThrow().status()).isEqualTo(PromptQualityMeasurements.DONE);
            assertThat(jdbc.queryForList("select outcome from ctxa_prompt_version_measure_answer where measure_id = ?",
                    String.class, tenant)).containsOnly(SealedDecisionReplayService.Outcome.ANSWERED.name());
            assertThat(drawn).hasSize(4);
            assertThat(drawn.subList(0, 2)).noneMatch(prompt -> prompt.contains("Tenant closing"));
            assertThat(drawn.subList(2, 4)).allMatch(prompt -> prompt.contains("=== Tenant closing (reference"
                    + " written by your organization) ===") && prompt.contains("export the ledger on the last"));
        }
        finally {
            measurements.close();
            line.close();
        }
    }
}
