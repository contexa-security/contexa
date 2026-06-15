package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricCatalog;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCasePublisher;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.sealed.DefaultOfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexaiam.admin.promptquality.official.api.OfficialPromptQualityInspectionController;
import io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialConsoleApiController;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultOfficialPromptQualityInspectionService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialPromptQualityInspectionService;
import io.contexa.contexaiam.admin.promptquality.official.web.PromptQualityAssurancePageController;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.jdbc.core.JdbcOperations;

@AutoConfiguration
@AutoConfigureAfter(IamAdminCenterAutoConfiguration.class)
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

    @Bean(name = "pqaOfficialPromptQualityInspectionService")
    @ConditionalOnMissingBean(OfficialPromptQualityInspectionService.class)
    public OfficialPromptQualityInspectionService pqaOfficialPromptQualityInspectionService(
            OfficialSealedEvidenceVerificationRuntime runtime) {
        return new DefaultOfficialPromptQualityInspectionService(runtime);
    }

    @Bean(name = "pqaOfficialPromptQualityInspectionController")
    @ConditionalOnMissingBean(OfficialPromptQualityInspectionController.class)
    public OfficialPromptQualityInspectionController pqaOfficialPromptQualityInspectionController(
            OfficialPromptQualityInspectionService inspectionService) {
        return new OfficialPromptQualityInspectionController(inspectionService);
    }

    @Bean(name = "pqaPromptQualityOfficialConsoleApiController")
    @ConditionalOnMissingBean(PromptQualityOfficialConsoleApiController.class)
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public PromptQualityOfficialConsoleApiController pqaPromptQualityOfficialConsoleApiController(
            SealedEvidencePackageLookupService evidenceLookupService,
            OfficialPromptQualityInspectionService inspectionService,
            OfficialVerificationRunStore runStore,
            ObjectMapper objectMapper,
            @Qualifier("contexaJdbcTemplate") JdbcOperations jdbcOperations) {
        return new PromptQualityOfficialConsoleApiController(
                evidenceLookupService,
                inspectionService,
                runStore,
                objectMapper,
                jdbcOperations);
    }

    @Bean(name = "pqaPromptQualityAssurancePageController")
    @ConditionalOnMissingBean(PromptQualityAssurancePageController.class)
    public PromptQualityAssurancePageController pqaPromptQualityAssurancePageController() {
        return new PromptQualityAssurancePageController();
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
