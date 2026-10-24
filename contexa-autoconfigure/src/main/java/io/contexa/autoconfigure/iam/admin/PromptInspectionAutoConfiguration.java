package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore;
import io.contexa.contexacore.autonomous.company.CompanyRecordsFactSourceVerifier;
import io.contexa.contexacore.autonomous.company.InMemoryCompanyRecordStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.inspection.PromptFactSourceVerifier;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCleanPackageRetentionScheduler;
import io.contexa.contexacore.verification.inspection.PromptInspectionReinspection;
import io.contexa.contexacore.verification.inspection.PromptInspectionResultStore;
import io.contexa.contexacore.verification.inspection.PromptInspectionScheduler;
import io.contexa.contexacore.verification.inspection.PromptInspectionService;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import io.contexa.contexacore.verification.inspection.SameFactCheck;
import io.contexa.contexacore.verification.inspection.SourceTruthCheck;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.inspection.BundleTraceCheck;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionResultStore;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptReleaseLookup;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionApiController;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionConsole;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionPageController;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplayApiController;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.inspection.SealIntegrityCheck;

/**
 * OSS prompt inspection: the inspector, the result store in the OSS schema, the automatic round that inspects every
 * sealed package once on the scheduler's thread, the operator's re-inspection on its own executor, the short retention
 * of the packages it found nothing wrong in (R4-S5), and the inspection
 * console (its read model, API and three screens). Nothing here
 * runs on a decision thread. Enterprise keeps sealed packages in its own schema, so none of these beans are created
 * while Enterprise is enabled.
 */
@AutoConfiguration(after = {PromptGovernanceAutoConfiguration.class, SealedEvidenceStoreAutoConfiguration.class,
        PqaSealedEvidenceAutoConfiguration.class})
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "false", matchIfMissing = true)
@ConditionalOnProperty(prefix = "contexa.prompt-inspection", name = "enabled", havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties({PromptInspectionProperties.class, PqaOssSealedEvidenceCaptureProperties.class})
public class PromptInspectionAutoConfiguration {

    /**
     * docs/agent OC-4: the source truth check reads Contexa's own company records and delegations again, unless the
     * application declares its own verifier of its sources.
     */
    @Bean
    @ConditionalOnMissingBean(PromptFactSourceVerifier.class)
    public PromptFactSourceVerifier companyRecordsFactSourceVerifier(
            ObjectProvider<CompanyRecordStore> companyRecordStore,
            ObjectProvider<DelegationRegistry> delegationRegistry) {
        return new CompanyRecordsFactSourceVerifier(companyRecordStore.getIfAvailable(InMemoryCompanyRecordStore::new),
                delegationRegistry.getIfAvailable());
    }

    /**
     * docs/agent OC-5: the operator's replay of a sealed decision with a chosen bundle, through the engine's prompt
     * template and pipeline; without them the replay API answers that the replay is not available.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SealedEvidencePackageRepository.class)
    public SealedDecisionReplays sealedDecisionReplays(
            SealedEvidencePackageRepository sealedEvidencePackageRepository,
            ObjectProvider<SecurityDecisionStandardPromptTemplate> templates,
            ObjectProvider<PipelineOrchestrator> pipelines,
            ObjectProvider<BaselineLearningService> baselineLearning,
            ObjectProvider<TieredStrategyProperties> tieredProperties,
            ObjectProvider<SecurityZeroTrustProperties> zeroTrustProperties,
            ObjectProvider<StructuredOutputCapabilityRegistry> structuredOutput,
            ObjectProvider<ModelSelectionStrategy> modelSelection,
            ObjectProvider<CanonicalSecurityContextSerializer> serializers,
            ObjectProvider<BaselineDataStore> baselineDataStore,
            ObjectProvider<CentralAuditFacade> auditFacade,
            ObjectMapper objectMapper) {
        ObjectMapper tolerant = objectMapper.copy().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        Supplier<SealedDecisionReplayService> service = () -> {
            SecurityDecisionStandardPromptTemplate template = templates.getIfAvailable();
            PipelineOrchestrator pipeline = pipelines.getIfAvailable();
            BaselineLearningService baselines = baselineLearning.getIfAvailable();
            if (template == null || pipeline == null || baselines == null) {
                return null;
            }
            SecurityZeroTrustProperties zeroTrust = zeroTrustProperties.getIfAvailable(SecurityZeroTrustProperties::new);
            return new SealedDecisionReplayService(template, pipeline, baselines,
                    tieredProperties.getIfAvailable(TieredStrategyProperties::new),
                    structuredOutput.getIfAvailable(StructuredOutputCapabilityRegistry::defaultRegistry),
                    modelSelection::getIfAvailable, zeroTrust.getMinimumAction().toRules(),
                    zeroTrust.getMinimumAction().getMode().name(),
                    serializers.getIfAvailable(() -> new CanonicalSecurityContextSerializer(tolerant)), tolerant);
        };
        return new SealedDecisionReplays(sealedEvidencePackageRepository, service, baselineDataStore.getIfAvailable(),
                auditFacade.getIfAvailable(), objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SealedDecisionReplays.class)
    public SealedDecisionReplayApiController sealedDecisionReplayApiController(SealedDecisionReplays sealedDecisionReplays) {
        return new SealedDecisionReplayApiController(sealedDecisionReplays);
    }

    /**
     * The core checks with the bundle trace right after the seal integrity. The trace reads the release registry when
     * the prompt version management keeps one; otherwise it says the trace cannot be checked.
     */
    @Bean
    @ConditionalOnMissingBean
    public PromptInspector promptInspector(
            ObjectMapper objectMapper,
            ObjectProvider<PromptGovernanceRegistryService> registryService,
            ObjectProvider<PromptFactSourceVerifier> sourceVerifier,
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations,
            ObjectProvider<SealedEvidencePackageIntegrity> integrity) {
        List<PromptInspectionCheck> checks = new ArrayList<>(PromptInspector.coreChecks());
        // docs/agent A5-6: the seal check verifies a schema 3 package's signature with the store's signer.
        SealedEvidencePackageIntegrity sealIntegrity = integrity.getIfAvailable();
        if (sealIntegrity != null) {
            checks.replaceAll(check -> check instanceof SealIntegrityCheck ? new SealIntegrityCheck(sealIntegrity)
                    : check);
        }
        JdbcOperations jdbc = jdbcOperations.getIfAvailable();
        checks.add(1, new BundleTraceCheck(registryService.getIfAvailable() != null && jdbc != null
                ? new JdbcPromptReleaseLookup(jdbc) : null));
        // W6-7: the host's own records of the facts, compared before the same-fact check.
        int sameFact = checks.stream().map(PromptInspectionCheck::code).toList().indexOf(SameFactCheck.CODE);
        checks.add(sameFact < 0 ? checks.size() : sameFact, new SourceTruthCheck(sourceVerifier.getIfAvailable()));
        return new PromptInspector(checks, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = {"contexaJdbcTemplate", "contexaTransactionManager"})
    public PromptInspectionResultStore promptInspectionResultStore(
            @Qualifier("contexaJdbcTemplate") JdbcOperations jdbcOperations,
            @Qualifier("contexaTransactionManager") PlatformTransactionManager transactionManager,
            ObjectMapper objectMapper) {
        return new JdbcPromptInspectionResultStore(jdbcOperations, new TransactionTemplate(transactionManager),
                objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({SealedEvidencePackageRepository.class, PromptInspectionResultStore.class})
    public PromptInspectionService promptInspectionService(
            PromptInspector promptInspector,
            SealedEvidencePackageRepository sealedEvidencePackageRepository,
            PromptInspectionResultStore promptInspectionResultStore) {
        return new PromptInspectionService(promptInspector, sealedEvidencePackageRepository,
                promptInspectionResultStore, Clock.systemUTC());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptInspectionService.class)
    public PromptInspectionScheduler promptInspectionScheduler(
            PromptInspectionService promptInspectionService,
            PromptInspectionProperties properties) {
        return new PromptInspectionScheduler(promptInspectionService, properties.getBatchSize(),
                properties.getSamplePercent());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptInspectionService.class)
    public PromptInspectionReinspection promptInspectionReinspection(
            PromptInspectionService promptInspectionService,
            PromptInspectionResultStore promptInspectionResultStore,
            PromptInspectionProperties properties) {
        return new PromptInspectionReinspection(promptInspectionService, promptInspectionResultStore,
                properties.getSamplePercent());
    }

    /**
     * R4-S5: the short retention of the packages whose latest inspection found nothing wrong, on the sealed package
     * retention's schedule and switch.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({SealedEvidencePackageRepository.class, PromptInspectionResultStore.class})
    @ConditionalOnProperty(prefix = "contexa.pqa.oss.sealed-evidence.retention", name = "enabled",
            havingValue = "true", matchIfMissing = true)
    public PromptInspectionCleanPackageRetentionScheduler promptInspectionCleanPackageRetentionScheduler(
            PromptInspectionResultStore promptInspectionResultStore,
            PqaOssSealedEvidenceCaptureProperties sealedEvidenceProperties) {
        return new PromptInspectionCleanPackageRetentionScheduler(promptInspectionResultStore,
                sealedEvidenceProperties.getRetention().getCleanPeriod());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public JdbcPromptInspectionQueries promptInspectionQueries(
            @Qualifier("contexaJdbcTemplate") JdbcOperations jdbcOperations) {
        return new JdbcPromptInspectionQueries(jdbcOperations);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptInspectionService.class)
    public PromptInspectionConsole promptInspectionConsole(
            SealedEvidencePackageRepository sealedEvidencePackageRepository,
            PromptInspector promptInspector,
            PromptInspectionResultStore promptInspectionResultStore,
            ObjectMapper objectMapper) {
        return new PromptInspectionConsole(sealedEvidencePackageRepository, promptInspector,
                promptInspectionResultStore, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptInspectionConsole.class, JdbcPromptInspectionQueries.class})
    public PromptInspectionApiController promptInspectionApiController(
            JdbcPromptInspectionQueries promptInspectionQueries,
            PromptInspectionConsole promptInspectionConsole,
            PromptInspectionReinspection promptInspectionReinspection) {
        return new PromptInspectionApiController(promptInspectionQueries, promptInspectionConsole,
                promptInspectionReinspection, Clock.systemUTC());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptInspectionConsole.class)
    public PromptInspectionPageController promptInspectionPageController(
            MessageSource messageSource,
            ObjectMapper objectMapper) {
        return new PromptInspectionPageController(messageSource, objectMapper);
    }
}
