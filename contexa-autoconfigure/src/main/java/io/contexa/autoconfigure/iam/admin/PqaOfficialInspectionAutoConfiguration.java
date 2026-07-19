package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.verification.adjudication.SealedEvidencePromptScorecard;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupPort;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricCatalog;
import io.contexa.contexacore.verification.persistence.VerificationLedgerService;
import io.contexa.contexacore.verification.prompt.VerificationPromptReplayBuilder;
import io.contexa.contexacore.verification.replay.DeterministicReplayService;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCasePublisher;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.sealed.DefaultOfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialConsoleApiController;
import io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialConsoleViewAssembler;
import io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialMetricApiController;
import io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialResourceApiController;
import io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialRuntimeEvidenceApiController;
import io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialVerificationRunApiController;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityOfficialMetricCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialRunLightweightEvidenceReader;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialRunMetricContractView;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityRuntimeCertificationPolicy;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityRuntimeEvidenceService;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityRuntimeVerificationService;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultRuntimeEvidencePromptScorecardService;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultRuntimeEvidencePromptConsistencyGate;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultRuntimeEvidenceReplayService;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultSealedEvidencePackageQueryService;
import io.contexa.contexaiam.admin.promptquality.official.application.JdbcOfficialVerificationExecutionLockService;
import io.contexa.contexaiam.admin.promptquality.official.application.ExecutionLockOfficialVerificationVerdictQueryService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationVerdictQueryService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationFailureAssembler;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationCustomerNarrativeAssembler;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricContract;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricResultAssembler;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationCurrentResultCoordinator;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationProgressRecorder;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationEvidencePreflight;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLedger;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationResourceResolver;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationReverificationCoordinator;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationResultCoordinator;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationResultAssembler;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptComparisonAssembler;
import io.contexa.contexaiam.admin.promptquality.official.application.SealedPromptEvidenceComparisonAssembler;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptComparisonValueInterpreter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotAssembler;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationActualPromptProblemRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialPromptFieldDefinitionWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationActualPromptProblemWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationActualPromptProblemLinker;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationLedgerWriters;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricPurposeWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricPurposeEvidenceWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptSignalWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptLineageWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptFieldStateWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptQualityIssueSynchronizer;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationAuditSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationAuditSnapshotWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationFindingRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationFindingWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricSnapshotWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptComparisonRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptComparisonWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPurposeEvidenceRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationRemediationGroupRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationRemediationGroupWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationReverificationResultRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationRunBatchWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotQueryService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotCompletionRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotRelationIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationCustomerPurposeIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationCustomerDisplayIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotIntegrityRepositories;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationContractLinkIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotReadModel;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotCleanupRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotCommandWriters;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionWriters;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationReverificationWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationMetricExecutionReferenceWriter;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityAssuranceCaseService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialMetricCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityProtectableResourceLookup;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeCertificationPolicy;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptRuntimeGovernanceDescriptorVerifier;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeEvidenceService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeVerificationService;
import io.contexa.contexaiam.admin.promptquality.official.application.RuntimeEvidencePromptConsistencyGate;
import io.contexa.contexaiam.admin.promptquality.official.application.RuntimeEvidencePromptScorecardService;
import io.contexa.contexaiam.admin.promptquality.official.application.RuntimeEvidenceReplayService;
import io.contexa.contexaiam.admin.promptquality.official.application.RuntimeIssueDiagnosticService;
import io.contexa.contexaiam.admin.promptquality.official.application.SealedEvidencePackageQueryService;
import io.contexa.contexaiam.admin.promptquality.official.common.DefaultPromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractCatalogBootstrap;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractCatalogWriter;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationCurrentResultCoordinator;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationSnapshotCompletionRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationSnapshotRelationIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationCustomerPurposeIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationCustomerDisplayIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationContractLinkIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationActualPromptProblemRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialPromptFieldDefinitionWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationReverificationWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationMetricExecutionReferenceWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationActualPromptProblemWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationActualPromptProblemLinker;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptQualityIssueSynchronizer;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationMetricPurposeWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationMetricPurposeEvidenceWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptSignalWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptLineageWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptFieldStateWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationAuditSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationAuditSnapshotWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationFindingRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationFindingWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationMetricSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationMetricSnapshotWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptComparisonRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptComparisonWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPurposeEvidenceRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationRemediationGroupRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationRemediationGroupWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationReverificationResultRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationRunBatchWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcSealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.OfficialVerificationSnapshotRowMapper;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationSnapshotCleanupRepository;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.process.JdbcPromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.state.DefaultPromptQualityStateCatalog;
import io.contexa.contexaiam.admin.promptquality.official.state.PromptQualityStateCatalog;
import io.contexa.contexaiam.admin.promptquality.official.web.PromptQualityAssurancePageController;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.MessageSource;
import org.springframework.core.Ordered;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.List;
import java.util.Optional;

@AutoConfiguration
@AutoConfigureAfter(
        value = IamAdminCenterAutoConfiguration.class,
        name = "io.contexa.autoconfigure.enterprise.iam.IamEnterpriseAutoConfiguration")
@ConditionalOnClass(OfficialSealedEvidenceVerificationRuntime.class)
@ConditionalOnBean(PromptQualityAssuranceCaseService.class)
@EnableConfigurationProperties({
        PromptQualityRouteProperties.class,
        PromptQualityOfficialVerificationProperties.class
})
public class PqaOfficialInspectionAutoConfiguration {

    @Bean(name = "promptQualityRouteModelAdvice")
    @ConditionalOnMissingBean(PromptQualityRouteModelAdvice.class)
    public PromptQualityRouteModelAdvice promptQualityRouteModelAdvice(PromptQualityRouteProperties properties) {
        return new PromptQualityRouteModelAdvice(properties);
    }

    @Bean(name = "pqaOfficialVerificationMetricCatalog")
    @ConditionalOnMissingBean(OfficialVerificationMetricCatalog.class)
    public OfficialVerificationMetricCatalog pqaOfficialVerificationMetricCatalog() {
        return new OfficialVerificationMetricCatalog();
    }

    @Bean(name = "pqaOfficialVerificationRunStore")
    @ConditionalOnMissingBean(OfficialVerificationRunStore.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationRunStore pqaJdbcOfficialVerificationRunStore(
            @Qualifier("contexaJdbcTemplate") JdbcOperations jdbcOperations,
            ObjectMapper objectMapper) {
        return new JdbcOfficialVerificationRunStore(jdbcOperations, objectMapper);
    }

    @Bean(name = "pqaOfficialVerificationCasePublisher")
    @ConditionalOnMissingBean(OfficialVerificationCasePublisher.class)
    public OfficialVerificationCasePublisher pqaOfficialVerificationCasePublisher() {
        return (userId, record) -> {
            // OSS official inspection stops after storing the official run.
        };
    }

    @Bean(name = "pqaPromptQualityMessageResolver")
    @ConditionalOnMissingBean(PromptQualityMessageResolver.class)
    public PromptQualityMessageResolver pqaPromptQualityMessageResolver(MessageSource messageSource) {
        return new DefaultPromptQualityMessageResolver(messageSource);
    }

    @Bean(name = "pqaOfficialVerificationMessageResolver")
    @ConditionalOnMissingBean(OfficialVerificationMessageResolver.class)
    public OfficialVerificationMessageResolver pqaOfficialVerificationMessageResolver(
            PromptQualityMessageResolver messageResolver) {
        return messageResolver::resolveRequired;
    }
    @Bean(name = "pqaOfficialMetricPurposeContractCatalogWriter")
    @ConditionalOnMissingBean(value = OfficialMetricPurposeContractWriter.class,
            name = "officialMetricPurposeContractCatalogWriter")
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialMetricPurposeContractCatalogWriter pqaOfficialMetricPurposeContractCatalogWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        return new OfficialMetricPurposeContractCatalogWriter(jdbcTemplate, objectMapper);
    }

    @Bean(name = "pqaOfficialMetricPurposeContractCatalogBootstrap")
    @DependsOn("iamSeedDataInitializer")
    @ConditionalOnMissingBean(name = {
            "officialMetricPurposeContractCatalogBootstrap",
            "pqaOfficialMetricPurposeContractCatalogBootstrap",
            "enterpriseResolutionContractCatalogBootstrap"
    })
    @ConditionalOnBean(name = "iamSeedDataInitializer")
    @ConditionalOnProperty(prefix = "contexa.pqa.official.contract-seed",
            name = "enabled", havingValue = "true", matchIfMissing = true)
    public OfficialMetricPurposeContractCatalogBootstrap pqaOfficialMetricPurposeContractCatalogBootstrap(
            OfficialMetricPurposeContractWriter writer) {
        return new OfficialMetricPurposeContractCatalogBootstrap(writer);
    }

    @Bean(name = "pqaSealedEvidencePackageIntegrity")
    @ConditionalOnMissingBean(SealedEvidencePackageIntegrity.class)
    public SealedEvidencePackageIntegrity pqaSealedEvidencePackageIntegrity() {
        return new SealedEvidencePackageIntegrity();
    }

    @Bean(name = "pqaSealedEvidencePackageRepository")
    @ConditionalOnMissingBean(SealedEvidencePackageRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public SealedEvidencePackageRepository pqaSealedEvidencePackageRepository(
            @Qualifier("contexaJdbcTemplate") JdbcOperations jdbcOperations) {
        return new JdbcSealedEvidencePackageRepository(jdbcOperations);
    }

    @Bean(name = "pqaSealedEvidencePackageLookupService")
    @ConditionalOnMissingBean(SealedEvidencePackageLookupPort.class)
    public SealedEvidencePackageLookupService pqaSealedEvidencePackageLookupService(
            SealedEvidencePackageRepository repository,
            SealedEvidencePackageIntegrity integrity) {
        return new SealedEvidencePackageLookupService(repository, integrity);
    }

    @Bean(name = "pqaOfficialSealedEvidenceVerificationRuntime")
    @ConditionalOnMissingBean(OfficialSealedEvidenceVerificationRuntime.class)
    public OfficialSealedEvidenceVerificationRuntime pqaOfficialSealedEvidenceVerificationRuntime(
            SealedEvidencePackageLookupPort evidenceLookupService,
            OfficialVerificationMetricCatalog metricCatalog,
            OfficialVerificationRunStore runStore,
            OfficialVerificationCasePublisher casePublisher,
            ObjectMapper objectMapper,
            OfficialVerificationMessageResolver messageResolver) {
        return new DefaultOfficialSealedEvidenceVerificationRuntime(
                evidenceLookupService,
                metricCatalog,
                runStore,
                casePublisher,
                objectMapper,
                messageResolver);
    }

    @Bean(name = "pqaSealedEvidencePackageQueryService")
    @ConditionalOnMissingBean(SealedEvidencePackageQueryService.class)
    public SealedEvidencePackageQueryService pqaSealedEvidencePackageQueryService(
            SealedEvidencePackageLookupPort evidenceLookupService,
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new DefaultSealedEvidencePackageQueryService(evidenceLookupService, jdbcTemplate);
    }

    @Bean(name = "pqaVerificationLedgerService")
    @ConditionalOnMissingBean(VerificationLedgerService.class)
    public VerificationLedgerService pqaVerificationLedgerService(OfficialVerificationRunStore runStore) {
        return new VerificationLedgerService(runStore);
    }

    @Bean(name = "pqaRuntimeEvidencePromptConsistencyGate")
    @ConditionalOnMissingBean(RuntimeEvidencePromptConsistencyGate.class)
    public RuntimeEvidencePromptConsistencyGate pqaRuntimeEvidencePromptConsistencyGate(
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver) {
        return new DefaultRuntimeEvidencePromptConsistencyGate(objectMapper, messageResolver);
    }

    @Bean(name = "pqaPromptQualityRuntimeEvidenceService")
    @ConditionalOnMissingBean(PromptQualityRuntimeEvidenceService.class)
    public PromptQualityRuntimeEvidenceService pqaPromptQualityRuntimeEvidenceService(
            SealedEvidencePackageQueryService queryService,
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            PromptQualityStateCatalog stateCatalog,
            PromptQualityProcessRunService processRunService) {
        return new DefaultPromptQualityRuntimeEvidenceService(
                queryService,
                objectMapper,
                messageResolver,
                promptConsistencyGate,
                stateCatalog,
                processRunService);
    }

    @Bean(name = "pqaPromptQualityOfficialMetricCatalog")
    @ConditionalOnMissingBean(PromptQualityOfficialMetricCatalog.class)
    public PromptQualityOfficialMetricCatalog pqaPromptQualityOfficialMetricCatalog(
            OfficialVerificationMetricCatalog metricCatalog) {
        return new DefaultPromptQualityOfficialMetricCatalog(metricCatalog);
    }

    @Bean(name = "pqaCanonicalSecurityContextSerializer")
    @ConditionalOnMissingBean(CanonicalSecurityContextSerializer.class)
    public CanonicalSecurityContextSerializer pqaCanonicalSecurityContextSerializer(ObjectMapper objectMapper) {
        return new CanonicalSecurityContextSerializer(objectMapper);
    }

    @Bean(name = "pqaVerificationPromptReplayBuilder")
    @ConditionalOnMissingBean(VerificationPromptReplayBuilder.class)
    public VerificationPromptReplayBuilder pqaVerificationPromptReplayBuilder() {
        return new VerificationPromptReplayBuilder();
    }

    @Bean(name = "pqaDeterministicReplayService")
    @ConditionalOnMissingBean(DeterministicReplayService.class)
    public DeterministicReplayService pqaDeterministicReplayService(
            SealedEvidencePackageLookupPort evidenceLookupService,
            CanonicalSecurityContextSerializer contextSerializer,
            PromptContextComposer promptContextComposer,
            SealedEvidencePackageIntegrity integrity,
            VerificationPromptReplayBuilder promptReplayBuilder) {
        return new DeterministicReplayService(
                evidenceLookupService,
                contextSerializer,
                promptContextComposer,
                integrity,
                promptReplayBuilder);
    }

    @Bean(name = "pqaSealedEvidencePromptScorecard")
    @ConditionalOnMissingBean(SealedEvidencePromptScorecard.class)
    public SealedEvidencePromptScorecard pqaSealedEvidencePromptScorecard(ObjectMapper objectMapper) {
        return new SealedEvidencePromptScorecard(objectMapper);
    }

    @Bean(name = "pqaRuntimeEvidenceReplayService")
    @ConditionalOnMissingBean(RuntimeEvidenceReplayService.class)
    public RuntimeEvidenceReplayService pqaRuntimeEvidenceReplayService(
            DeterministicReplayService replayService) {
        return new DefaultRuntimeEvidenceReplayService(replayService);
    }

    @Bean(name = "pqaRuntimeEvidencePromptScorecardService")
    @ConditionalOnMissingBean(RuntimeEvidencePromptScorecardService.class)
    public RuntimeEvidencePromptScorecardService pqaRuntimeEvidencePromptScorecardService(
            SealedEvidencePromptScorecard promptScorecard) {
        return new DefaultRuntimeEvidencePromptScorecardService(promptScorecard);
    }

    @Bean(name = "pqaPromptQualityRuntimeCertificationPolicy")
    @ConditionalOnMissingBean(PromptQualityRuntimeCertificationPolicy.class)
    public PromptQualityRuntimeCertificationPolicy pqaPromptQualityRuntimeCertificationPolicy(
            ObjectMapper objectMapper,
            PromptRuntimeGovernanceDescriptorVerifier governanceDescriptorVerifier,
            PromptQualityMessageResolver messageResolver) {
        return new DefaultPromptQualityRuntimeCertificationPolicy(
                objectMapper,
                governanceDescriptorVerifier,
                messageResolver);
    }

    @Bean(name = "pqaPromptQualityStateCatalog")
    @ConditionalOnMissingBean(PromptQualityStateCatalog.class)
    public PromptQualityStateCatalog pqaPromptQualityStateCatalog() {
        return new DefaultPromptQualityStateCatalog();
    }

    @Bean(name = "pqaPromptQualityProcessRunService")
    @ConditionalOnMissingBean(PromptQualityProcessRunService.class)
    public PromptQualityProcessRunService pqaPromptQualityProcessRunService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        return new JdbcPromptQualityProcessRunService(jdbcTemplate, objectMapper);
    }

    @Bean(name = "pqaOfficialVerificationSnapshotRepository")
    @ConditionalOnMissingBean(OfficialVerificationSnapshotRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationSnapshotRepository pqaOfficialVerificationSnapshotRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationSnapshotRepository(jdbcTemplate);
    }

    @Bean(name = "pqaOfficialVerificationSnapshotCleanupRepository")
    @ConditionalOnMissingBean(OfficialVerificationSnapshotCleanupRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationSnapshotCleanupRepository pqaOfficialVerificationSnapshotCleanupRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationSnapshotCleanupRepository(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialPromptFieldDefinitionWriter")
    @ConditionalOnMissingBean(OfficialPromptFieldDefinitionWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialPromptFieldDefinitionWriter pqaOfficialPromptFieldDefinitionWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        return new JdbcOfficialPromptFieldDefinitionWriter(jdbcTemplate, objectMapper);
    }
    @Bean(name = "pqaOfficialVerificationActualPromptProblemWriter")
    @ConditionalOnMissingBean(OfficialVerificationActualPromptProblemWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationActualPromptProblemWriter pqaOfficialVerificationActualPromptProblemWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationActualPromptProblemWriter(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationPromptQualityIssueSynchronizer")
    @ConditionalOnMissingBean(OfficialVerificationPromptQualityIssueSynchronizer.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationPromptQualityIssueSynchronizer pqaOfficialVerificationPromptQualityIssueSynchronizer(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationPromptQualityIssueSynchronizer(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationPromptComparisonWriter")
    @ConditionalOnMissingBean(OfficialVerificationPromptComparisonWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationPromptComparisonWriter pqaOfficialVerificationPromptComparisonWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationPromptComparisonWriter(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationRemediationGroupWriter")
    @ConditionalOnMissingBean(OfficialVerificationRemediationGroupWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationRemediationGroupWriter pqaOfficialVerificationRemediationGroupWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationRemediationGroupWriter(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationFindingWriter")
    @ConditionalOnMissingBean(OfficialVerificationFindingWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationFindingWriter pqaOfficialVerificationFindingWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationFindingWriter(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationMetricSnapshotWriter")
    @ConditionalOnMissingBean(OfficialVerificationMetricSnapshotWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationMetricSnapshotWriter pqaOfficialVerificationMetricSnapshotWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        return new JdbcOfficialVerificationMetricSnapshotWriter(jdbcTemplate, objectMapper);
    }
    @Bean(name = "pqaOfficialVerificationMetricPurposeWriter")
    @ConditionalOnMissingBean(OfficialVerificationMetricPurposeWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationMetricPurposeWriter pqaOfficialVerificationMetricPurposeWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationMetricPurposeWriter(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationMetricPurposeEvidenceWriter")
    @ConditionalOnMissingBean(OfficialVerificationMetricPurposeEvidenceWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationMetricPurposeEvidenceWriter pqaOfficialVerificationMetricPurposeEvidenceWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationMetricPurposeEvidenceWriter(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationPromptSignalWriter")
    @ConditionalOnMissingBean(OfficialVerificationPromptSignalWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationPromptSignalWriter pqaOfficialVerificationPromptSignalWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationPromptSignalWriter(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationActualPromptProblemLinker")
    @ConditionalOnMissingBean(OfficialVerificationActualPromptProblemLinker.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationActualPromptProblemLinker pqaOfficialVerificationActualPromptProblemLinker(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationActualPromptProblemLinker(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationPromptLineageWriter")
    @ConditionalOnMissingBean(OfficialVerificationPromptLineageWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationPromptLineageWriter pqaOfficialVerificationPromptLineageWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationPromptLineageWriter(jdbcTemplate);
    }

    @Bean(name = "pqaOfficialVerificationPromptFieldStateWriter")
    @ConditionalOnMissingBean(OfficialVerificationPromptFieldStateWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationPromptFieldStateWriter pqaOfficialVerificationPromptFieldStateWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationPromptFieldStateWriter(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationLedgerWriters")
    @ConditionalOnMissingBean(OfficialVerificationLedgerWriters.class)
    public OfficialVerificationLedgerWriters pqaOfficialVerificationLedgerWriters(
            OfficialVerificationActualPromptProblemWriter actualPromptProblemWriter,
            OfficialVerificationPromptQualityIssueSynchronizer promptQualityIssueSynchronizer,
            OfficialVerificationMetricPurposeWriter metricPurposeWriter,
            OfficialVerificationMetricPurposeEvidenceWriter metricPurposeEvidenceWriter,
            OfficialVerificationPromptSignalWriter promptSignalWriter,
            OfficialVerificationActualPromptProblemLinker actualPromptProblemLinker,
            OfficialVerificationPromptLineageWriter promptLineageWriter,
            OfficialVerificationPromptFieldStateWriter promptFieldStateWriter) {
        return new OfficialVerificationLedgerWriters(
                actualPromptProblemWriter, promptQualityIssueSynchronizer, metricPurposeWriter,
                metricPurposeEvidenceWriter, promptSignalWriter, actualPromptProblemLinker,
                promptLineageWriter, promptFieldStateWriter);
    }
    @Bean(name = "pqaOfficialVerificationReverificationWriter")
    @ConditionalOnMissingBean(OfficialVerificationReverificationWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationReverificationWriter pqaOfficialVerificationReverificationWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationReverificationWriter(jdbcTemplate);
    }

    @Bean(name = "pqaOfficialVerificationMetricExecutionReferenceWriter")
    @ConditionalOnMissingBean(OfficialVerificationMetricExecutionReferenceWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationMetricExecutionReferenceWriter pqaOfficialVerificationMetricExecutionReferenceWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationMetricExecutionReferenceWriter(jdbcTemplate);
    }

    @Bean(name = "pqaOfficialVerificationExecutionWriters")
    @ConditionalOnMissingBean(OfficialVerificationExecutionWriters.class)
    public OfficialVerificationExecutionWriters pqaOfficialVerificationExecutionWriters(
            OfficialVerificationReverificationWriter reverificationWriter,
            OfficialVerificationMetricExecutionReferenceWriter metricExecutionReferenceWriter) {
        return new OfficialVerificationExecutionWriters(reverificationWriter, metricExecutionReferenceWriter);
    }
    @Bean(name = "pqaOfficialVerificationSnapshotCommandWriters")
    @ConditionalOnMissingBean(OfficialVerificationSnapshotCommandWriters.class)
    public OfficialVerificationSnapshotCommandWriters pqaOfficialVerificationSnapshotCommandWriters(
            OfficialVerificationAuditSnapshotWriter auditSnapshotWriter,
            OfficialVerificationRunBatchWriter runBatchWriter,
            OfficialVerificationMetricSnapshotWriter metricSnapshotWriter,
            OfficialVerificationFindingWriter findingWriter,
            OfficialVerificationRemediationGroupWriter remediationGroupWriter,
            OfficialVerificationPromptComparisonWriter promptComparisonWriter,
            OfficialPromptFieldDefinitionWriter promptFieldDefinitionWriter,
            OfficialVerificationExecutionWriters executionWriters) {
        return new OfficialVerificationSnapshotCommandWriters(
                auditSnapshotWriter, runBatchWriter, metricSnapshotWriter, findingWriter, remediationGroupWriter,
                promptComparisonWriter, promptFieldDefinitionWriter, executionWriters);
    }
    @Bean(name = "pqaOfficialVerificationRunBatchWriter")
    @ConditionalOnMissingBean(OfficialVerificationRunBatchWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationRunBatchWriter pqaOfficialVerificationRunBatchWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationRunBatchWriter(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationAuditSnapshotWriter")
    @ConditionalOnMissingBean(OfficialVerificationAuditSnapshotWriter.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationAuditSnapshotWriter pqaOfficialVerificationAuditSnapshotWriter(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        return new JdbcOfficialVerificationAuditSnapshotWriter(jdbcTemplate, objectMapper);
    }
    @Bean(name = "pqaOfficialVerificationSnapshotRowMapper")
    @ConditionalOnMissingBean(OfficialVerificationSnapshotRowMapper.class)
    public OfficialVerificationSnapshotRowMapper pqaOfficialVerificationSnapshotRowMapper(ObjectMapper objectMapper) {
        return new OfficialVerificationSnapshotRowMapper(objectMapper);
    }

    @Bean(name = "pqaOfficialVerificationMetricSnapshotRepository")
    @ConditionalOnMissingBean(OfficialVerificationMetricSnapshotRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationMetricSnapshotRepository pqaOfficialVerificationMetricSnapshotRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        return new JdbcOfficialVerificationMetricSnapshotRepository(jdbcTemplate, rowMapper);
    }

    @Bean(name = "pqaOfficialVerificationFindingRepository")
    @ConditionalOnMissingBean(OfficialVerificationFindingRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationFindingRepository pqaOfficialVerificationFindingRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        return new JdbcOfficialVerificationFindingRepository(jdbcTemplate, rowMapper);
    }

    @Bean(name = "pqaOfficialVerificationRemediationGroupRepository")
    @ConditionalOnMissingBean(OfficialVerificationRemediationGroupRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationRemediationGroupRepository pqaOfficialVerificationRemediationGroupRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        return new JdbcOfficialVerificationRemediationGroupRepository(jdbcTemplate, rowMapper);
    }

    @Bean(name = "pqaOfficialVerificationPromptComparisonRepository")
    @ConditionalOnMissingBean(OfficialVerificationPromptComparisonRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationPromptComparisonRepository pqaOfficialVerificationPromptComparisonRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        return new JdbcOfficialVerificationPromptComparisonRepository(jdbcTemplate, rowMapper);
    }

    @Bean(name = "pqaOfficialVerificationActualPromptProblemRepository")
    @ConditionalOnMissingBean(OfficialVerificationActualPromptProblemRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationActualPromptProblemRepository pqaOfficialVerificationActualPromptProblemRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        return new JdbcOfficialVerificationActualPromptProblemRepository(jdbcTemplate, rowMapper);
    }

    @Bean(name = "pqaOfficialVerificationPurposeEvidenceRepository")
    @ConditionalOnMissingBean(OfficialVerificationPurposeEvidenceRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationPurposeEvidenceRepository pqaOfficialVerificationPurposeEvidenceRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        return new JdbcOfficialVerificationPurposeEvidenceRepository(jdbcTemplate, rowMapper);
    }

    @Bean(name = "pqaOfficialVerificationAuditSnapshotRepository")
    @ConditionalOnMissingBean(OfficialVerificationAuditSnapshotRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationAuditSnapshotRepository pqaOfficialVerificationAuditSnapshotRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        return new JdbcOfficialVerificationAuditSnapshotRepository(jdbcTemplate, rowMapper);
    }

    @Bean(name = "pqaOfficialVerificationReverificationResultRepository")
    @ConditionalOnMissingBean(OfficialVerificationReverificationResultRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationReverificationResultRepository pqaOfficialVerificationReverificationResultRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            OfficialVerificationSnapshotRowMapper rowMapper) {
        return new JdbcOfficialVerificationReverificationResultRepository(jdbcTemplate, rowMapper);
    }

    @Bean(name = "pqaOfficialVerificationSnapshotReadModel")
    @ConditionalOnMissingBean(OfficialVerificationSnapshotReadModel.class)
    public OfficialVerificationSnapshotReadModel pqaOfficialVerificationSnapshotReadModel(
            OfficialVerificationMetricSnapshotRepository metricRepository,
            OfficialVerificationFindingRepository findingRepository,
            OfficialVerificationRemediationGroupRepository remediationRepository,
            OfficialVerificationPromptComparisonRepository comparisonRepository,
            OfficialVerificationActualPromptProblemRepository problemRepository,
            OfficialVerificationPurposeEvidenceRepository purposeRepository,
            OfficialVerificationAuditSnapshotRepository auditRepository,
            OfficialVerificationReverificationResultRepository reverificationRepository) {
        return new OfficialVerificationSnapshotReadModel(
                metricRepository, findingRepository, remediationRepository, comparisonRepository,
                problemRepository, purposeRepository, auditRepository, reverificationRepository);
    }

    @Bean(name = "pqaOfficialVerificationSnapshotCompletionRepository")
    @ConditionalOnMissingBean(OfficialVerificationSnapshotCompletionRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationSnapshotCompletionRepository pqaOfficialVerificationSnapshotCompletionRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationSnapshotCompletionRepository(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationSnapshotRelationIntegrityRepository")
    @ConditionalOnMissingBean(OfficialVerificationSnapshotRelationIntegrityRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationSnapshotRelationIntegrityRepository pqaOfficialVerificationSnapshotRelationIntegrityRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationSnapshotRelationIntegrityRepository(jdbcTemplate);
    }

    @Bean(name = "pqaOfficialVerificationCustomerPurposeIntegrityRepository")
    @ConditionalOnMissingBean(OfficialVerificationCustomerPurposeIntegrityRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationCustomerPurposeIntegrityRepository pqaOfficialVerificationCustomerPurposeIntegrityRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationCustomerPurposeIntegrityRepository(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationCustomerDisplayIntegrityRepository")
    @ConditionalOnMissingBean(OfficialVerificationCustomerDisplayIntegrityRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationCustomerDisplayIntegrityRepository pqaOfficialVerificationCustomerDisplayIntegrityRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationCustomerDisplayIntegrityRepository(jdbcTemplate);
    }

    @Bean(name = "pqaOfficialVerificationContractLinkIntegrityRepository")
    @ConditionalOnMissingBean(OfficialVerificationContractLinkIntegrityRepository.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationContractLinkIntegrityRepository pqaOfficialVerificationContractLinkIntegrityRepository(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationContractLinkIntegrityRepository(jdbcTemplate);
    }
    @Bean(name = "pqaOfficialVerificationSnapshotIntegrityRepositories")
    @ConditionalOnMissingBean(OfficialVerificationSnapshotIntegrityRepositories.class)
    public OfficialVerificationSnapshotIntegrityRepositories pqaOfficialVerificationSnapshotIntegrityRepositories(
            OfficialVerificationSnapshotCompletionRepository completionRepository,
            OfficialVerificationSnapshotRelationIntegrityRepository relationIntegrityRepository,
            OfficialVerificationCustomerPurposeIntegrityRepository customerPurposeIntegrityRepository,
            OfficialVerificationCustomerDisplayIntegrityRepository customerDisplayIntegrityRepository,
            OfficialVerificationContractLinkIntegrityRepository contractLinkIntegrityRepository) {
        return new OfficialVerificationSnapshotIntegrityRepositories(
                completionRepository, relationIntegrityRepository,
                customerPurposeIntegrityRepository, customerDisplayIntegrityRepository, contractLinkIntegrityRepository);
    }
    @Bean(name = "pqaOfficialVerificationSnapshotQueryService")
    @ConditionalOnMissingBean(OfficialVerificationSnapshotQueryService.class)
    public OfficialVerificationSnapshotQueryService pqaOfficialVerificationSnapshotQueryService(
            OfficialVerificationSnapshotRepository batchRepository,
            OfficialVerificationSnapshotReadModel readModel,
            OfficialVerificationSnapshotAssembler snapshotAssembler,
            OfficialVerificationSnapshotIntegrityRepositories integrityRepositories) {
        return new OfficialVerificationSnapshotQueryService(
                batchRepository,
                readModel,
                snapshotAssembler,
                OfficialVerificationOperatorSnapshotService.DIAGNOSTIC_CATALOG_VERSION,
                integrityRepositories);
    }
    @Bean(name = "pqaOfficialVerificationSnapshotAssembler")
    @ConditionalOnMissingBean(OfficialVerificationSnapshotAssembler.class)
    public OfficialVerificationSnapshotAssembler pqaOfficialVerificationSnapshotAssembler() {
        return new OfficialVerificationSnapshotAssembler();
    }

    @Bean(name = "pqaOfficialVerificationCurrentResultCoordinator")
    @ConditionalOnMissingBean(OfficialVerificationCurrentResultCoordinator.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationCurrentResultCoordinator pqaOfficialVerificationCurrentResultCoordinator(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new JdbcOfficialVerificationCurrentResultCoordinator(jdbcTemplate);
    }

    @Bean(name = "pqaOfficialVerificationOperatorSnapshotService")
    @ConditionalOnMissingBean(OfficialVerificationOperatorSnapshotService.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationOperatorSnapshotService pqaOfficialVerificationOperatorSnapshotService(
            ObjectMapper objectMapper,
            OfficialMetricPurposeContractWriter contractCatalogWriter,
            OfficialVerificationSnapshotCleanupRepository snapshotCleanupRepository,
            OfficialVerificationSnapshotQueryService snapshotQueryService,
            OfficialVerificationSnapshotCommandWriters commandWriters,
            OfficialVerificationLedgerWriters ledgerWriters,
            OfficialVerificationCurrentResultCoordinator currentResultCoordinator,
            PromptQualityMessageResolver messageResolver) {
        return new OfficialVerificationOperatorSnapshotService(
                objectMapper,
                contractCatalogWriter,
                snapshotCleanupRepository,
                snapshotQueryService,
                commandWriters,
                ledgerWriters,
                currentResultCoordinator,
                messageResolver::resolveRequired);
    }
    @Bean(name = "pqaPromptQualityOfficialRunDetailService")
    @ConditionalOnMissingBean(PromptQualityOfficialRunDetailService.class)
    public PromptQualityOfficialRunDetailService pqaPromptQualityOfficialRunDetailService(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService verificationLedgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver,
            PromptQualityAssuranceCaseService assuranceCaseService,
            PromptQualityProcessRunService processRunService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate) {
        OfficialRunLightweightEvidenceReader evidenceReader = new OfficialRunLightweightEvidenceReader(
                jdbcTemplate,
                objectMapper,
                promptConsistencyGate,
                evidenceService,
                messageResolver);
        OfficialRunMetricContractView metricContractView = new OfficialRunMetricContractView(
                metricCatalog,
                FinalPromptMetricContractCatalog.load(objectMapper));
        return new DefaultPromptQualityOfficialRunDetailService(
                officialRuntime,
                verificationLedgerService,
                evidenceReader,
                metricContractView,
                messageResolver,
                assuranceCaseService,
                processRunService,
                operatorSnapshotService);
    }

    @Bean(name = "pqaOfficialVerificationExecutionLockService")
    @ConditionalOnMissingBean(OfficialVerificationExecutionLockService.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationExecutionLockService pqaOfficialVerificationExecutionLockService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            PromptQualityOfficialVerificationProperties properties) {
        return new JdbcOfficialVerificationExecutionLockService(
                jdbcTemplate,
                objectMapper,
                properties.getStaleExecutionTimeout());
    }

    @Bean(name = "pqaOfficialVerificationVerdictQueryService")
    @ConditionalOnMissingBean(OfficialVerificationVerdictQueryService.class)
    @ConditionalOnBean(OfficialVerificationExecutionLockService.class)
    public OfficialVerificationVerdictQueryService pqaOfficialVerificationVerdictQueryService(
            OfficialVerificationExecutionLockService executionLockService) {
        return new ExecutionLockOfficialVerificationVerdictQueryService(executionLockService);
    }
    @Bean(name = "pqaPromptComparisonValueInterpreter")
    @ConditionalOnMissingBean(PromptComparisonValueInterpreter.class)
    public PromptComparisonValueInterpreter pqaPromptComparisonValueInterpreter(
            PromptQualityMessageResolver messageResolver) {
        return new PromptComparisonValueInterpreter(messageResolver);
    }

    @Bean(name = "pqaSealedPromptEvidenceComparisonAssembler")
    @ConditionalOnMissingBean(SealedPromptEvidenceComparisonAssembler.class)
    public SealedPromptEvidenceComparisonAssembler pqaSealedPromptEvidenceComparisonAssembler(
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver,
            PromptComparisonValueInterpreter values) {
        return new SealedPromptEvidenceComparisonAssembler(objectMapper, messageResolver, values);
    }

    @Bean(name = "pqaOfficialVerificationPromptComparisonAssembler")
    @ConditionalOnMissingBean(OfficialVerificationPromptComparisonAssembler.class)
    public OfficialVerificationPromptComparisonAssembler pqaOfficialVerificationPromptComparisonAssembler(
            SealedPromptEvidenceComparisonAssembler sealedEvidenceAssembler,
            PromptComparisonValueInterpreter values,
            PromptQualityMessageResolver messageResolver) {
        return new OfficialVerificationPromptComparisonAssembler(
                sealedEvidenceAssembler,
                values,
                messageResolver);
    }
    @Bean(name = "pqaOfficialVerificationResourceResolver")
    @ConditionalOnMissingBean(OfficialVerificationResourceResolver.class)
    public OfficialVerificationResourceResolver pqaOfficialVerificationResourceResolver(
            PromptQualityProtectableResourceLookup resourceLookup) {
        return new OfficialVerificationResourceResolver(resourceLookup);
    }

    @Bean(name = "pqaOfficialVerificationEvidencePreflight")
    @ConditionalOnMissingBean(OfficialVerificationEvidencePreflight.class)
    public OfficialVerificationEvidencePreflight pqaOfficialVerificationEvidencePreflight(
            SealedEvidencePackageQueryService queryService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            OfficialVerificationResourceResolver resourceResolver,
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver) {
        return new OfficialVerificationEvidencePreflight(
                queryService,
                replayService,
                promptScorecardService,
                promptConsistencyGate,
                resourceResolver,
                objectMapper,
                messageResolver);
    }
    @Bean(name = "pqaOfficialVerificationResultAssembler")
    @ConditionalOnMissingBean(OfficialVerificationResultAssembler.class)
    public OfficialVerificationResultAssembler pqaOfficialVerificationResultAssembler(
            OfficialVerificationFailureAssembler failureAssembler,
            OfficialVerificationPromptComparisonAssembler promptComparisonAssembler,
            OfficialVerificationMetricResultAssembler metricResultAssembler,
            OfficialVerificationCustomerNarrativeAssembler customerNarrativeAssembler) {
        return new OfficialVerificationResultAssembler(
                failureAssembler,
                promptComparisonAssembler,
                metricResultAssembler,
                customerNarrativeAssembler);
    }

    @Bean(name = "pqaOfficialVerificationResultCoordinator")
    @ConditionalOnMissingBean(OfficialVerificationResultCoordinator.class)
    public OfficialVerificationResultCoordinator pqaOfficialVerificationResultCoordinator(
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService issueDiagnosticService,
            OfficialVerificationProgressRecorder progressRecorder,
            OfficialVerificationResultAssembler resultAssembler,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            OfficialVerificationExecutionLedger executionLedger,
            PromptQualityMessageResolver messageResolver) {
        return new OfficialVerificationResultCoordinator(
                assuranceCaseService,
                issueDiagnosticService,
                progressRecorder,
                resultAssembler,
                operatorSnapshotService,
                executionLedger,
                messageResolver);
    }
    @Bean(name = "pqaOfficialVerificationExecutionLedger")
    @ConditionalOnMissingBean(OfficialVerificationExecutionLedger.class)
    public OfficialVerificationExecutionLedger pqaOfficialVerificationExecutionLedger(
            OfficialVerificationExecutionLockService executionLockService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            OfficialVerificationMetricContract metricContract,
            OfficialVerificationEvidencePreflight evidencePreflight,
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver) {
        return new OfficialVerificationExecutionLedger(
                executionLockService,
                operatorSnapshotService,
                metricContract,
                evidencePreflight,
                objectMapper,
                messageResolver);
    }
    @Bean(name = "pqaOfficialVerificationMetricContract")
    @ConditionalOnMissingBean(OfficialVerificationMetricContract.class)
    public OfficialVerificationMetricContract pqaOfficialVerificationMetricContract(
            PromptQualityOfficialMetricCatalog metricCatalog,
            OfficialSealedEvidenceVerificationRuntime runtime) {
        return new OfficialVerificationMetricContract(metricCatalog, runtime);
    }
    @Bean(name = "pqaOfficialVerificationCustomerNarrativeAssembler")
    @ConditionalOnMissingBean(OfficialVerificationCustomerNarrativeAssembler.class)
    public OfficialVerificationCustomerNarrativeAssembler pqaOfficialVerificationCustomerNarrativeAssembler(
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver) {
        return new OfficialVerificationCustomerNarrativeAssembler(metricCatalog, messageResolver);
    }
    @Bean(name = "pqaOfficialVerificationMetricResultAssembler")
    @ConditionalOnMissingBean(OfficialVerificationMetricResultAssembler.class)
    public OfficialVerificationMetricResultAssembler pqaOfficialVerificationMetricResultAssembler(
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver) {
        return new OfficialVerificationMetricResultAssembler(metricCatalog, messageResolver);
    }
    @Bean(name = "pqaOfficialVerificationFailureAssembler")
    @ConditionalOnMissingBean(OfficialVerificationFailureAssembler.class)
    public OfficialVerificationFailureAssembler pqaOfficialVerificationFailureAssembler(
            PromptQualityMessageResolver messageResolver) {
        return new OfficialVerificationFailureAssembler(messageResolver);
    }
    @Bean(name = "pqaOfficialVerificationReverificationCoordinator")
    @ConditionalOnMissingBean(OfficialVerificationReverificationCoordinator.class)
    public OfficialVerificationReverificationCoordinator pqaOfficialVerificationReverificationCoordinator(
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            OfficialVerificationProgressRecorder progressRecorder,
            PromptQualityMessageResolver messageResolver) {
        return new OfficialVerificationReverificationCoordinator(
                operatorSnapshotService,
                progressRecorder,
                messageResolver);
    }
    @Bean(name = "pqaOfficialVerificationProgressRecorder")
    @ConditionalOnMissingBean(OfficialVerificationProgressRecorder.class)
    public OfficialVerificationProgressRecorder pqaOfficialVerificationProgressRecorder(
            PromptQualityProcessRunService processRunService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            OfficialVerificationExecutionLockService executionLockService,
            PromptQualityMessageResolver messageResolver) {
        return new OfficialVerificationProgressRecorder(
                processRunService,
                operatorSnapshotService,
                executionLockService,
                messageResolver);
    }
    @Bean(name = "pqaPromptQualityRuntimeVerificationService")
    @ConditionalOnMissingBean(PromptQualityRuntimeVerificationService.class)
    public PromptQualityRuntimeVerificationService pqaPromptQualityRuntimeVerificationService(
            OfficialSealedEvidenceVerificationRuntime runtime,
            OfficialVerificationEvidencePreflight evidencePreflight,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            OfficialVerificationMetricContract metricContract,
            OfficialVerificationProgressRecorder progressRecorder,
            OfficialVerificationExecutionLedger executionLedger,
            OfficialVerificationResultCoordinator resultCoordinator,
            OfficialVerificationReverificationCoordinator reverificationCoordinator) {
        return new DefaultPromptQualityRuntimeVerificationService(
                runtime,
                evidencePreflight,
                certificationPolicy,
                metricContract,
                progressRecorder,
                executionLedger,
                resultCoordinator,
                reverificationCoordinator);
    }

    @Bean(name = "pqaPromptQualityOfficialConsoleViewAssembler")
    @ConditionalOnMissingBean(PromptQualityOfficialConsoleViewAssembler.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public PromptQualityOfficialConsoleViewAssembler pqaPromptQualityOfficialConsoleViewAssembler(
            SealedEvidencePackageLookupPort evidenceLookupService,
            PromptQualityOfficialRunDetailService runDetailService,
            OfficialVerificationRunStore runStore,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            PromptQualityMessageResolver messageResolver) {
        return new PromptQualityOfficialConsoleViewAssembler(
                evidenceLookupService,
                runDetailService,
                runStore,
                objectMapper,
                promptConsistencyGate,
                messageResolver);
    }

    @Bean(name = "pqaPromptQualityOfficialConsoleApiController")
    @ConditionalOnMissingBean(PromptQualityOfficialConsoleApiController.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public PromptQualityOfficialConsoleApiController pqaPromptQualityOfficialConsoleApiController(
            PromptQualityOfficialConsoleViewAssembler views) {
        return new PromptQualityOfficialConsoleApiController(views);
    }

    @Bean(name = "pqaPromptQualityOfficialResourceApiController")
    @ConditionalOnMissingBean(PromptQualityOfficialResourceApiController.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public PromptQualityOfficialResourceApiController pqaPromptQualityOfficialResourceApiController(
            PromptQualityOfficialConsoleViewAssembler views) {
        return new PromptQualityOfficialResourceApiController(views);
    }

    @Bean(name = "pqaPromptQualityOfficialRuntimeEvidenceApiController")
    @ConditionalOnMissingBean(PromptQualityOfficialRuntimeEvidenceApiController.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public PromptQualityOfficialRuntimeEvidenceApiController pqaPromptQualityOfficialRuntimeEvidenceApiController(
            PromptQualityRuntimeEvidenceService runtimeEvidenceService,
            PromptQualityOfficialConsoleViewAssembler views) {
        return new PromptQualityOfficialRuntimeEvidenceApiController(runtimeEvidenceService, views);
    }

    @Bean(name = "pqaPromptQualityOfficialMetricApiController")
    @ConditionalOnMissingBean(PromptQualityOfficialMetricApiController.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public PromptQualityOfficialMetricApiController pqaPromptQualityOfficialMetricApiController(
            PromptQualityOfficialRunDetailService runDetailService,
            PromptQualityOfficialConsoleViewAssembler views) {
        return new PromptQualityOfficialMetricApiController(runDetailService, views);
    }

    @Bean(name = "pqaPromptQualityOfficialVerificationRunApiController")
    @ConditionalOnMissingBean(PromptQualityOfficialVerificationRunApiController.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public PromptQualityOfficialVerificationRunApiController pqaPromptQualityOfficialVerificationRunApiController(
            PromptQualityRuntimeVerificationService verificationService,
            PromptQualityOfficialRunDetailService runDetailService,
            PromptQualityOfficialConsoleViewAssembler views) {
        return new PromptQualityOfficialVerificationRunApiController(
                verificationService, runDetailService, views);
    }

    @Bean(name = "pqaPromptQualityAssurancePageController")
    @ConditionalOnMissingBean(PromptQualityAssurancePageController.class)
    public PromptQualityAssurancePageController pqaPromptQualityAssurancePageController(
            PromptQualityMessageResolver messageResolver) {
        return new PromptQualityAssurancePageController(messageResolver);
    }

    @Bean(name = "pqaOssOfficialSealedEvidenceCaptureService")
    @ConditionalOnMissingBean(OssOfficialSealedEvidenceCaptureService.class)
    @ConditionalOnProperty(prefix = "contexa.pqa.oss.sealed-evidence", name = "capture-enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "false", matchIfMissing = true)
    public OssOfficialSealedEvidenceCaptureService pqaOssOfficialSealedEvidenceCaptureService(
            SealedEvidencePackageRepository repository,
            SealedEvidencePackageIntegrity integrity,
            ObjectMapper objectMapper) {
        return new OssOfficialSealedEvidenceCaptureService(repository, integrity, objectMapper);
    }

    @Bean(name = "pqaOssOfficialSealedEvidenceCaptureFilter")
    @ConditionalOnMissingBean(name = "pqaOssOfficialSealedEvidenceCaptureFilter")
    @ConditionalOnBean(OssOfficialSealedEvidenceCaptureService.class)
    @ConditionalOnProperty(prefix = "contexa.pqa.oss.sealed-evidence", name = "capture-enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "false", matchIfMissing = true)
    public FilterRegistrationBean<OssOfficialSealedEvidenceCaptureFilter> pqaOssOfficialSealedEvidenceCaptureFilter(
            OssOfficialSealedEvidenceCaptureService captureService) {
        FilterRegistrationBean<OssOfficialSealedEvidenceCaptureFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new OssOfficialSealedEvidenceCaptureFilter(captureService));
        registration.setName("pqaOssOfficialSealedEvidenceCaptureFilter");
        registration.addUrlPatterns("/api/*");
        registration.setOrder(Ordered.LOWEST_PRECEDENCE - 20);
        return registration;
    }
}
