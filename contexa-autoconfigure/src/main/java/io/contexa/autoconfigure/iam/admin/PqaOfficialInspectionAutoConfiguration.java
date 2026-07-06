package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.verification.adjudication.SealedEvidencePromptScorecard;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricCatalog;
import io.contexa.contexacore.verification.persistence.VerificationLedgerService;
import io.contexa.contexacore.verification.prompt.VerificationPromptReplayBuilder;
import io.contexa.contexacore.verification.replay.DeterministicReplayService;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCasePublisher;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.sealed.DefaultOfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialConsoleApiController;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityOfficialMetricCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityRuntimeCertificationPolicy;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityRuntimeEvidenceService;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityRuntimeVerificationService;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultRuntimeEvidencePromptScorecardService;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultRuntimeEvidencePromptConsistencyGate;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultRuntimeEvidenceReplayService;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultSealedEvidencePackageQueryService;
import io.contexa.contexaiam.admin.promptquality.official.application.JdbcOfficialVerificationExecutionLockService;
import io.contexa.contexaiam.admin.promptquality.official.application.NoopPromptQualityAssuranceCaseService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityAssuranceCaseService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityCertificateService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialMetricCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityProtectableResourceLookup;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeCertificationPolicy;
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
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.process.NoopPromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.web.PromptQualityAssurancePageController;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.List;
import java.util.Optional;

@AutoConfiguration
@AutoConfigureAfter(
        value = IamAdminCenterAutoConfiguration.class,
        name = "io.contexa.autoconfigure.enterprise.iam.IamEnterpriseAutoConfiguration")
@ConditionalOnClass(OfficialSealedEvidenceVerificationRuntime.class)
public class PqaOfficialInspectionAutoConfiguration {

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

    @Bean(name = "pqaOfficialMetricPurposeContractCatalogWriter")
    @ConditionalOnMissingBean(value = OfficialMetricPurposeContractCatalogWriter.class,
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
            "pqaOfficialMetricPurposeContractCatalogBootstrap"
    })
    @ConditionalOnBean(name = "iamSeedDataInitializer")
    @ConditionalOnProperty(prefix = "contexa.pqa.official.contract-seed",
            name = "enabled", havingValue = "true", matchIfMissing = true)
    public OfficialMetricPurposeContractCatalogBootstrap pqaOfficialMetricPurposeContractCatalogBootstrap(
            OfficialMetricPurposeContractCatalogWriter writer) {
        return new OfficialMetricPurposeContractCatalogBootstrap(writer);
    }

    @Bean(name = "pqaSealedEvidencePackageIntegrity")
    @ConditionalOnMissingBean(SealedEvidencePackageIntegrity.class)
    public SealedEvidencePackageIntegrity pqaSealedEvidencePackageIntegrity() {
        return new SealedEvidencePackageIntegrity();
    }

    @Bean(name = "pqaSealedEvidencePackageLookupService")
    @ConditionalOnMissingBean(SealedEvidencePackageLookupService.class)
    public SealedEvidencePackageLookupService pqaSealedEvidencePackageLookupService(
            SealedEvidencePackageRepository repository,
            SealedEvidencePackageIntegrity integrity) {
        return new SealedEvidencePackageLookupService(repository, integrity);
    }

    @Bean(name = "pqaOfficialSealedEvidenceVerificationRuntime")
    @ConditionalOnMissingBean(OfficialSealedEvidenceVerificationRuntime.class)
    public OfficialSealedEvidenceVerificationRuntime pqaOfficialSealedEvidenceVerificationRuntime(
            SealedEvidencePackageLookupService evidenceLookupService,
            OfficialVerificationMetricCatalog metricCatalog,
            OfficialVerificationRunStore runStore,
            OfficialVerificationCasePublisher casePublisher,
            ObjectMapper objectMapper) {
        return new DefaultOfficialSealedEvidenceVerificationRuntime(
                evidenceLookupService,
                metricCatalog,
                runStore,
                casePublisher,
                objectMapper);
    }

    @Bean(name = "pqaSealedEvidencePackageQueryService")
    @ConditionalOnMissingBean(SealedEvidencePackageQueryService.class)
    public SealedEvidencePackageQueryService pqaSealedEvidencePackageQueryService(
            SealedEvidencePackageLookupService evidenceLookupService,
            JdbcTemplate jdbcTemplate) {
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
        return new DefaultRuntimeEvidencePromptConsistencyGate(objectMapper, null, messageResolver);
    }

    @Bean(name = "pqaPromptQualityRuntimeEvidenceService")
    @ConditionalOnMissingBean(PromptQualityRuntimeEvidenceService.class)
    public PromptQualityRuntimeEvidenceService pqaPromptQualityRuntimeEvidenceService(
            SealedEvidencePackageQueryService queryService,
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            PromptQualityProcessRunService processRunService) {
        return new DefaultPromptQualityRuntimeEvidenceService(
                queryService,
                objectMapper,
                messageResolver,
                promptConsistencyGate,
                null,
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
            SealedEvidencePackageLookupService evidenceLookupService,
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
            ObjectMapper objectMapper) {
        return new DefaultPromptQualityRuntimeCertificationPolicy(objectMapper, null);
    }

    @Bean(name = "pqaPromptQualityProtectableResourceLookup")
    @ConditionalOnMissingBean(PromptQualityProtectableResourceLookup.class)
    public PromptQualityProtectableResourceLookup pqaPromptQualityProtectableResourceLookup() {
        return (resourceUrl, resourceId, httpMethod) -> Optional.empty();
    }

    @Bean(name = "pqaPromptQualityCertificateService")
    @ConditionalOnMissingBean(PromptQualityCertificateService.class)
    public PromptQualityCertificateService pqaPromptQualityCertificateService() {
        return new PromptQualityCertificateService();
    }

    @Bean(name = "pqaPromptQualityAssuranceCaseService")
    @ConditionalOnMissingBean(PromptQualityAssuranceCaseService.class)
    public PromptQualityAssuranceCaseService pqaPromptQualityAssuranceCaseService() {
        return new NoopPromptQualityAssuranceCaseService();
    }

    @Bean(name = "pqaRuntimeIssueDiagnosticService")
    @ConditionalOnMissingBean(RuntimeIssueDiagnosticService.class)
    public RuntimeIssueDiagnosticService pqaRuntimeIssueDiagnosticService() {
        return (runId, packageId, httpMethod, metrics, nextActions) -> List.of();
    }

    @Bean(name = "pqaPromptQualityProcessRunService")
    @ConditionalOnMissingBean(PromptQualityProcessRunService.class)
    public PromptQualityProcessRunService pqaPromptQualityProcessRunService() {
        return new NoopPromptQualityProcessRunService();
    }

    @Bean(name = "pqaOfficialVerificationOperatorSnapshotService")
    @ConditionalOnMissingBean(OfficialVerificationOperatorSnapshotService.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationOperatorSnapshotService pqaOfficialVerificationOperatorSnapshotService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            ObjectProvider<OfficialMetricPurposeContractCatalogWriter> contractCatalogWriter) {
        return new OfficialVerificationOperatorSnapshotService(
                jdbcTemplate,
                objectMapper,
                contractCatalogWriter.getIfAvailable());
    }

    @Bean(name = "pqaPromptQualityOfficialRunDetailService")
    @ConditionalOnMissingBean(PromptQualityOfficialRunDetailService.class)
    public PromptQualityOfficialRunDetailService pqaPromptQualityOfficialRunDetailService(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService verificationLedgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver,
            PromptQualityCertificateService certificateService,
            PromptQualityAssuranceCaseService assuranceCaseService,
            PromptQualityProcessRunService processRunService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        return new DefaultPromptQualityOfficialRunDetailService(
                officialRuntime,
                verificationLedgerService,
                evidenceService,
                metricCatalog,
                messageResolver,
                certificateService,
                assuranceCaseService,
                processRunService,
                operatorSnapshotService,
                jdbcTemplateProvider.getIfAvailable());
    }

    @Bean(name = "pqaOfficialVerificationExecutionLockService")
    @ConditionalOnMissingBean(OfficialVerificationExecutionLockService.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public OfficialVerificationExecutionLockService pqaOfficialVerificationExecutionLockService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        return new JdbcOfficialVerificationExecutionLockService(jdbcTemplate, objectMapper);
    }

    @Bean(name = "pqaPromptQualityRuntimeVerificationService")
    @ConditionalOnMissingBean(PromptQualityRuntimeVerificationService.class)
    public PromptQualityRuntimeVerificationService pqaPromptQualityRuntimeVerificationService(
            SealedEvidencePackageQueryService queryService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            OfficialSealedEvidenceVerificationRuntime runtime,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            PromptQualityProtectableResourceLookup resourceLookup,
            PromptQualityCertificateService certificateService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService issueDiagnosticService,
            PromptQualityMessageResolver messageResolver,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            PromptQualityProcessRunService processRunService,
            OfficialVerificationExecutionLockService executionLockService) {
        return new DefaultPromptQualityRuntimeVerificationService(
                queryService,
                replayService,
                promptScorecardService,
                runtime,
                certificationPolicy,
                resourceLookup,
                certificateService,
                metricCatalog,
                assuranceCaseService,
                issueDiagnosticService,
                messageResolver,
                objectMapper,
                promptConsistencyGate,
                operatorSnapshotService,
                processRunService,
                executionLockService);
    }

    @Bean(name = "pqaPromptQualityOfficialConsoleApiController")
    @ConditionalOnMissingBean(PromptQualityOfficialConsoleApiController.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public PromptQualityOfficialConsoleApiController pqaPromptQualityOfficialConsoleApiController(
            SealedEvidencePackageLookupService evidenceLookupService,
            PromptQualityRuntimeVerificationService verificationService,
            PromptQualityOfficialRunDetailService runDetailService,
            OfficialVerificationRunStore runStore,
            ObjectMapper objectMapper,
            @Qualifier("contexaJdbcTemplate") JdbcOperations jdbcOperations,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            PromptQualityMessageResolver messageResolver) {
        return new PromptQualityOfficialConsoleApiController(
                evidenceLookupService,
                verificationService,
                runDetailService,
                runStore,
                objectMapper,
                jdbcOperations,
                promptConsistencyGate,
                messageResolver);
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
