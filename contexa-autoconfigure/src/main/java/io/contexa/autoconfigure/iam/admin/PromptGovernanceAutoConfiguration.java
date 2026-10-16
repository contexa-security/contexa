package io.contexa.autoconfigure.iam.admin;

import java.time.Clock;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexaiam.admin.promptquality.governance.PromptPolicySetLookup;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackApiController;
import io.contexa.contexaiam.admin.promptquality.governance.PromptReleaseTransitionApiController;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolver;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceEmpiricalEvalService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceJpaLedgerWriter;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceLifecycleLedgerService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceModelCompatibilityRegistryService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceDescriptorResolver;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceRuntimeCacheInvalidationService;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptReleaseQueryService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceRuntimeCacheInvalidationService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptReleaseApiController;
import io.contexa.contexaiam.admin.promptquality.governance.PromptReleaseConsole;
import io.contexa.contexaiam.admin.promptquality.governance.PromptReleaseConsoleApiController;
import io.contexa.contexaiam.admin.promptquality.governance.PromptReleasePageController;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.official.application.JdbcPromptRuntimeGovernanceDescriptorVerifier;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptRuntimeGovernanceDescriptorVerifier;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Prompt version management: the registry, its lifecycle ledger, release gate, evaluation and model compatibility
 * services, the startup registration, the ledger writer, the descriptor resolver, the runtime cache invalidation, the
 * descriptor verifier, the version query API (GET /contexa/admin/api/prompt-quality/releases) and the version
 * screens with their read API (W7-14).
 *
 * <p>One property, {@code contexa.prompt.governance.enabled} (default on, version management decision 11), turns all
 * of them on or off together, in an OSS-only installation as well as with the enterprise modules. The descriptor
 * verifier requires an active registry release, so it only exists when the registry service, and with it the startup
 * registration, exists (PV-22). The beans that depend on other beans of this class are declared after them, because
 * {@code @ConditionalOnBean} only sees the beans registered before it (PV-24). Registered before the official
 * inspection so the descriptor verifier precedes its none() default.
 */
@AutoConfiguration(after = CoreDataAutoConfiguration.class, before = PqaOfficialInspectionAutoConfiguration.class)
@ConditionalOnProperty(prefix = "contexa.prompt.governance", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PromptGovernanceAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PromptGovernanceRuntimeCacheInvalidationService promptGovernanceRuntimeCacheInvalidationService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate
    ) {
        return new JdbcPromptGovernanceRuntimeCacheInvalidationService(jdbcTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper
    ) {
        return new JdbcPromptGovernanceDescriptorResolver(jdbcTemplate, objectMapper);
    }

    /**
     * The registry implementation of the bundle selector (W3-16): the security decision runs the release of the
     * request's scope by its state and canary share when {@code contexa.security.tiered.prompt-bundle.selector} is
     * {@code registry}; otherwise it runs the configured bundle. It shares the resolver's cached releases when the
     * resolver is the JDBC resolver.
     */
    @Bean
    @ConditionalOnMissingBean(PromptBundleSelector.class)
    @ConditionalOnProperty(prefix = "contexa.security.tiered.prompt-bundle", name = "selector", havingValue = "registry")
    public PromptBundleSelector promptBundleSelector(
            PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver,
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper
    ) {
        JdbcPromptGovernanceDescriptorResolver registry =
                promptGovernanceDescriptorResolver instanceof JdbcPromptGovernanceDescriptorResolver jdbcResolver
                        ? jdbcResolver
                        : new JdbcPromptGovernanceDescriptorResolver(jdbcTemplate, objectMapper);
        return registry.registrySelector();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptGovernanceRegistryRepository.class, PromptGovernanceChangeRecordRepository.class, PromptGovernanceEvaluationRecordRepository.class, PromptGovernanceReleaseApprovalRepository.class, PromptGovernanceReleaseWorkflowRepository.class, PromptGovernanceRollbackRecordRepository.class})
    public PromptGovernanceJpaLedgerWriter promptGovernanceJpaLedgerWriter(
            PromptGovernanceRegistryRepository registryRepository,
            PromptGovernanceChangeRecordRepository changeRepository,
            PromptGovernanceEvaluationRecordRepository evaluationRepository,
            PromptGovernanceReleaseApprovalRepository releaseApprovalRepository,
            PromptGovernanceReleaseWorkflowRepository releaseWorkflowRepository,
            PromptGovernanceRollbackRecordRepository rollbackRepository
    ) {
        return new PromptGovernanceJpaLedgerWriter(
                registryRepository,
                changeRepository,
                evaluationRepository,
                releaseApprovalRepository,
                releaseWorkflowRepository,
                rollbackRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public JdbcPromptReleaseQueryService promptReleaseQueryService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate
    ) {
        return new JdbcPromptReleaseQueryService(jdbcTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptReleaseApiController promptReleaseApiController(JdbcPromptReleaseQueryService promptReleaseQueryService) {
        return new PromptReleaseApiController(promptReleaseQueryService);
    }

    /** W6-10: the bundle rollback, on this build's bundles; a host with policy sets gives a {@link PromptPolicySetLookup}. */
    @Bean
    @ConditionalOnMissingBean
    public PromptBundleRollbackService promptBundleRollbackService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            PromptGovernanceRuntimeCacheInvalidationService runtimeCacheInvalidationService,
            ObjectProvider<PromptPolicySetLookup> policySetLookup, ObjectMapper objectMapper) {
        return new PromptBundleRollbackService(jdbcTemplate, PromptBundleCatalog.shared(), runtimeCacheInvalidationService,
                policySetLookup.getIfAvailable(), objectMapper, Clock.systemUTC());
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptBundleRollbackApiController promptBundleRollbackApiController(
            PromptBundleRollbackService promptBundleRollbackService) {
        return new PromptBundleRollbackApiController(promptBundleRollbackService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptGovernanceRegistryRepository.class)
    public PromptGovernanceRegistryService promptGovernanceRegistryService(
            PromptGovernanceRegistryRepository promptGovernanceRegistryRepository) {
        return new PromptGovernanceRegistryService(promptGovernanceRegistryRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptGovernanceRegistryService.class, PromptGovernanceModelCompatibilityRepository.class, PromptGovernanceBudgetProfileRepository.class})
    public PromptGovernanceModelCompatibilityRegistryService promptGovernanceModelCompatibilityRegistryService(
            PromptGovernanceRegistryService promptGovernanceRegistryService,
            PromptGovernanceModelCompatibilityRepository promptGovernanceModelCompatibilityRepository,
            PromptGovernanceBudgetProfileRepository promptGovernanceBudgetProfileRepository) {
        return new PromptGovernanceModelCompatibilityRegistryService(
                promptGovernanceRegistryService,
                promptGovernanceModelCompatibilityRepository,
                promptGovernanceBudgetProfileRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptGovernanceRegistryService.class, PromptGovernanceChangeRecordRepository.class, PromptGovernanceEvaluationRecordRepository.class, PromptGovernanceReleaseApprovalRepository.class, PromptGovernanceRollbackRecordRepository.class})
    public PromptGovernanceLifecycleLedgerService promptGovernanceLifecycleLedgerService(
            PromptGovernanceRegistryService promptGovernanceRegistryService,
            PromptGovernanceChangeRecordRepository promptGovernanceChangeRecordRepository,
            PromptGovernanceEvaluationRecordRepository promptGovernanceEvaluationRecordRepository,
            PromptGovernanceReleaseApprovalRepository promptGovernanceReleaseApprovalRepository,
            PromptGovernanceRollbackRecordRepository promptGovernanceRollbackRecordRepository) {
        return new PromptGovernanceLifecycleLedgerService(
                promptGovernanceRegistryService,
                promptGovernanceChangeRecordRepository,
                promptGovernanceEvaluationRecordRepository,
                promptGovernanceReleaseApprovalRepository,
                promptGovernanceRollbackRecordRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptGovernanceLifecycleLedgerService.class, PromptGovernanceRegistryRepository.class, PromptGovernanceChangeRecordRepository.class, PromptGovernanceEvaluationRecordRepository.class, PromptGovernanceReleaseApprovalRepository.class, PromptGovernanceRollbackRecordRepository.class, PromptGovernanceReleaseWorkflowRepository.class, PromptGovernanceModelCompatibilityRepository.class, PromptGovernanceBudgetProfileRepository.class})
    public PromptGovernanceReleaseGateService promptGovernanceReleaseGateService(
            PromptGovernanceLifecycleLedgerService promptGovernanceLifecycleLedgerService,
            PromptGovernanceRegistryRepository promptGovernanceRegistryRepository,
            PromptGovernanceChangeRecordRepository promptGovernanceChangeRecordRepository,
            PromptGovernanceEvaluationRecordRepository promptGovernanceEvaluationRecordRepository,
            PromptGovernanceReleaseApprovalRepository promptGovernanceReleaseApprovalRepository,
            PromptGovernanceRollbackRecordRepository promptGovernanceRollbackRecordRepository,
            PromptGovernanceReleaseWorkflowRepository promptGovernanceReleaseWorkflowRepository,
            PromptGovernanceModelCompatibilityRepository promptGovernanceModelCompatibilityRepository,
            PromptGovernanceBudgetProfileRepository promptGovernanceBudgetProfileRepository) {
        return new PromptGovernanceReleaseGateService(
                promptGovernanceLifecycleLedgerService,
                promptGovernanceRegistryRepository,
                promptGovernanceChangeRecordRepository,
                promptGovernanceEvaluationRecordRepository,
                promptGovernanceReleaseApprovalRepository,
                promptGovernanceRollbackRecordRepository,
                promptGovernanceReleaseWorkflowRepository,
                promptGovernanceModelCompatibilityRepository,
                promptGovernanceBudgetProfileRepository);
    }

    /** W6-8: the operator's registry transitions through the release gate. */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptGovernanceReleaseGateService.class)
    public PromptReleaseTransitionApiController promptReleaseTransitionApiController(
            PromptGovernanceReleaseGateService promptGovernanceReleaseGateService,
            PromptGovernanceRuntimeCacheInvalidationService runtimeCacheInvalidationService) {
        return new PromptReleaseTransitionApiController(promptGovernanceReleaseGateService,
                runtimeCacheInvalidationService);
    }

    /**
     * W7-14: what the version screens show, from the registry, the release gate, the rollbacks and the sealed
     * decisions. The sealed decisions are read with the inspection read model, also where the inspection is off.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptGovernanceReleaseGateService.class)
    public PromptReleaseConsole promptReleaseConsole(
            JdbcPromptReleaseQueryService promptReleaseQueryService,
            PromptGovernanceReleaseGateService promptGovernanceReleaseGateService,
            PromptBundleRollbackService promptBundleRollbackService,
            ObjectProvider<JdbcPromptInspectionQueries> promptInspectionQueries,
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate) {
        return new PromptReleaseConsole(promptReleaseQueryService, promptGovernanceReleaseGateService,
                promptBundleRollbackService, PromptBundleCatalog.shared(),
                promptInspectionQueries.getIfAvailable(() -> new JdbcPromptInspectionQueries(jdbcTemplate)));
    }

    /** W7-14: the read API of the version screens (bundles, gate, compare). */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptReleaseConsole.class)
    public PromptReleaseConsoleApiController promptReleaseConsoleApiController(
            PromptReleaseConsole promptReleaseConsole) {
        return new PromptReleaseConsoleApiController(promptReleaseConsole, Clock.systemUTC());
    }

    /** W7-14: the version screens of the prompt quality console. */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptReleaseConsole.class)
    public PromptReleasePageController promptReleasePageController(MessageSource messageSource,
                                                                   ObjectMapper objectMapper) {
        return new PromptReleasePageController(messageSource, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptGovernanceRegistryRepository.class, PromptGovernanceEvaluationRecordRepository.class})
    public PromptGovernanceEmpiricalEvalService promptGovernanceEmpiricalEvalService(
            PromptGovernanceRegistryRepository promptGovernanceRegistryRepository,
            PromptGovernanceEvaluationRecordRepository promptGovernanceEvaluationRecordRepository) {
        return new PromptGovernanceEmpiricalEvalService(
                promptGovernanceRegistryRepository,
                promptGovernanceEvaluationRecordRepository);
    }

    @Bean
    @ConditionalOnMissingBean(name = "promptGovernanceRegistryBootstrapRunner")
    @ConditionalOnBean(PromptGovernanceRegistryService.class)
    public ApplicationRunner promptGovernanceRegistryBootstrapRunner(
            PromptGovernanceRegistryService promptGovernanceRegistryService,
            ObjectProvider<PromptGovernanceLifecycleLedgerService> promptGovernanceLifecycleLedgerService,
            ObjectProvider<PromptGovernanceModelCompatibilityRegistryService> promptGovernanceModelCompatibilityRegistryService) {
        // Registration of the platform prompts happens here only; the read paths no longer write. Each sync creates
        // missing rows and refreshes code-owned content, never the operational fields (version management PV-4).
        return args -> {
            promptGovernanceRegistryService.syncPlatformRegistry();
            promptGovernanceLifecycleLedgerService.ifAvailable(PromptGovernanceLifecycleLedgerService::syncPlatformLifecycleLedgers);
            promptGovernanceModelCompatibilityRegistryService.ifAvailable(PromptGovernanceModelCompatibilityRegistryService::syncPlatformRegistry);
        };
    }

    /** Only with the startup registration: the verifier requires an active registry release (PV-22). */
    @Bean
    @ConditionalOnMissingBean(PromptRuntimeGovernanceDescriptorVerifier.class)
    @ConditionalOnBean(PromptGovernanceRegistryService.class)
    public JdbcPromptRuntimeGovernanceDescriptorVerifier promptRuntimeGovernanceDescriptorVerifier(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            PromptQualityMessageResolver messageResolver
    ) {
        return new JdbcPromptRuntimeGovernanceDescriptorVerifier(jdbcTemplate, messageResolver);
    }
}
