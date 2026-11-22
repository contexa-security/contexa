package io.contexa.autoconfigure.iam.admin;

import java.time.Clock;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompts;
import io.contexa.contexaiam.admin.promptquality.governance.PromptPolicySetLookup;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexaiam.admin.promptquality.governance.JpaPromptGovernanceStatusWriter;
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
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Prompt version management: the registry, its lifecycle ledger, release gate, evaluation and model compatibility
 * services, the startup registration, the ledger writer, the descriptor resolver, the runtime cache invalidation, the
 * release query and the bundle rollback. The prompt version screens and their API, which took the place of the release
 * screens, are PromptVersionConsoleAutoConfiguration's (plan 6-6).
 *
 * <p>One property, {@code contexa.prompt.governance.enabled} (default on, version management decision 11), turns all
 * of them on or off together, in an OSS-only installation as well as with the enterprise modules. The beans that
 * depend on other beans of this class are declared after them, because {@code @ConditionalOnBean} only sees the beans
 * registered before it (PV-24).
 */
@AutoConfiguration(after = CoreDataAutoConfiguration.class)
@ConditionalOnProperty(prefix = "contexa.prompt.governance", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PromptGovernanceAutoConfiguration {

    @Bean(name = "contexaPromptGovernanceRuntimeCacheInvalidationService")
    @ConditionalOnMissingBean
    public PromptGovernanceRuntimeCacheInvalidationService promptGovernanceRuntimeCacheInvalidationService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate
    ) {
        return new JdbcPromptGovernanceRuntimeCacheInvalidationService(jdbcTemplate);
    }

    @Bean(name = "contexaPromptGovernanceDescriptorResolver")
    @ConditionalOnMissingBean
    public PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper
    ) {
        return new JdbcPromptGovernanceDescriptorResolver(jdbcTemplate, objectMapper);
    }

    /**
     * The registry implementation of the bundle selector (W3-16): the security decision runs the release of the
     * request's scope by its state and canary share when {@code contexa.security.tiered.prompt-bundle.selector} is
     * {@code registry}; otherwise it runs the configured bundle. It shares the resolver's cached releases when the
     * resolver is the JDBC resolver.
     */
    @Bean(name = "contexaPromptBundleSelector")
    @ConditionalOnMissingBean(PromptBundleSelector.class)
    @ConditionalOnProperty(prefix = "contexa.security.tiered.prompt-bundle", name = "selector", havingValue = "registry")
    public PromptBundleSelector promptBundleSelector(
            PromptGovernanceDescriptorResolver contexaPromptGovernanceDescriptorResolver,
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper
    ) {
        JdbcPromptGovernanceDescriptorResolver registry =
                contexaPromptGovernanceDescriptorResolver instanceof JdbcPromptGovernanceDescriptorResolver jdbcResolver
                        ? jdbcResolver
                        : new JdbcPromptGovernanceDescriptorResolver(jdbcTemplate, objectMapper);
        return registry.registrySelector();
    }

    @Bean(name = "contexaPromptGovernanceJpaLedgerWriter")
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

    @Bean(name = "contexaPromptReleaseQueryService")
    @ConditionalOnMissingBean
    public JdbcPromptReleaseQueryService promptReleaseQueryService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate
    ) {
        return new JdbcPromptReleaseQueryService(jdbcTemplate);
    }

    /**
     * W6-10: the rollback, on the versions of the database (plan 3.9) and on this build's bundles; a host with policy
     * sets gives a {@link PromptPolicySetLookup}.
     */
    @Bean(name = "contexaPromptBundleRollbackService")
    @ConditionalOnMissingBean
    public PromptBundleRollbackService promptBundleRollbackService(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            PromptGovernanceRuntimeCacheInvalidationService runtimeCacheInvalidationService,
            ObjectProvider<PromptPolicySetLookup> policySetLookup, @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            ObjectProvider<PromptGovernanceRegistryRepository> registryRepository,
            ObjectProvider<PromptGovernanceRollbackRecordRepository> rollbackRepository,
            ObjectProvider<PromptVersionCatalog> promptVersionCatalog) {
        return new PromptBundleRollbackService(jdbcTemplate,
                PromptBundleCatalog.shared().withVersions(promptVersionCatalog.getIfAvailable(PromptVersionCatalog::none)),
                runtimeCacheInvalidationService,
                policySetLookup.getIfAvailable(), objectMapper, Clock.systemUTC(),
                new JpaPromptGovernanceStatusWriter(registryRepository.getIfAvailable(), rollbackRepository.getIfAvailable()));
    }

    @Bean(name = "contexaPromptGovernanceRegistryService")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptGovernanceRegistryRepository.class)
    public PromptGovernanceRegistryService promptGovernanceRegistryService(
            PromptGovernanceRegistryRepository promptGovernanceRegistryRepository) {
        return new PromptGovernanceRegistryService(promptGovernanceRegistryRepository);
    }

    @Bean(name = "contexaPromptGovernanceModelCompatibilityRegistryService")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptGovernanceRegistryService.class, PromptGovernanceModelCompatibilityRepository.class, PromptGovernanceBudgetProfileRepository.class})
    public PromptGovernanceModelCompatibilityRegistryService promptGovernanceModelCompatibilityRegistryService(
            PromptGovernanceRegistryService contexaPromptGovernanceRegistryService,
            PromptGovernanceModelCompatibilityRepository promptGovernanceModelCompatibilityRepository,
            PromptGovernanceBudgetProfileRepository promptGovernanceBudgetProfileRepository) {
        return new PromptGovernanceModelCompatibilityRegistryService(
                contexaPromptGovernanceRegistryService,
                promptGovernanceModelCompatibilityRepository,
                promptGovernanceBudgetProfileRepository);
    }

    @Bean(name = "contexaPromptGovernanceLifecycleLedgerService")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptGovernanceRegistryService.class, PromptGovernanceChangeRecordRepository.class, PromptGovernanceEvaluationRecordRepository.class, PromptGovernanceReleaseApprovalRepository.class, PromptGovernanceRollbackRecordRepository.class})
    public PromptGovernanceLifecycleLedgerService promptGovernanceLifecycleLedgerService(
            PromptGovernanceRegistryService contexaPromptGovernanceRegistryService,
            PromptGovernanceChangeRecordRepository promptGovernanceChangeRecordRepository,
            PromptGovernanceEvaluationRecordRepository promptGovernanceEvaluationRecordRepository,
            PromptGovernanceReleaseApprovalRepository promptGovernanceReleaseApprovalRepository,
            PromptGovernanceRollbackRecordRepository promptGovernanceRollbackRecordRepository) {
        return new PromptGovernanceLifecycleLedgerService(
                contexaPromptGovernanceRegistryService,
                promptGovernanceChangeRecordRepository,
                promptGovernanceEvaluationRecordRepository,
                promptGovernanceReleaseApprovalRepository,
                promptGovernanceRollbackRecordRepository);
    }

    @Bean(name = "contexaPromptGovernanceReleaseGateService")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptGovernanceLifecycleLedgerService.class, PromptGovernanceRegistryRepository.class, PromptGovernanceChangeRecordRepository.class, PromptGovernanceEvaluationRecordRepository.class, PromptGovernanceReleaseApprovalRepository.class, PromptGovernanceRollbackRecordRepository.class, PromptGovernanceReleaseWorkflowRepository.class, PromptGovernanceModelCompatibilityRepository.class, PromptGovernanceBudgetProfileRepository.class})
    public PromptGovernanceReleaseGateService promptGovernanceReleaseGateService(
            PromptGovernanceLifecycleLedgerService contexaPromptGovernanceLifecycleLedgerService,
            PromptGovernanceRegistryRepository promptGovernanceRegistryRepository,
            PromptGovernanceChangeRecordRepository promptGovernanceChangeRecordRepository,
            PromptGovernanceEvaluationRecordRepository promptGovernanceEvaluationRecordRepository,
            PromptGovernanceReleaseApprovalRepository promptGovernanceReleaseApprovalRepository,
            PromptGovernanceRollbackRecordRepository promptGovernanceRollbackRecordRepository,
            PromptGovernanceReleaseWorkflowRepository promptGovernanceReleaseWorkflowRepository,
            PromptGovernanceModelCompatibilityRepository promptGovernanceModelCompatibilityRepository,
            PromptGovernanceBudgetProfileRepository promptGovernanceBudgetProfileRepository,
            ObjectProvider<PromptVersionCatalog> promptVersionCatalog,
            ObjectProvider<VersionedPrompts> versionedPrompts) {
        // Plan 3.9: a release named as a version (v2.0) is read from the version table and its product policy, which
        // the product of each prompt declares: the security decision and the other prompts (plan 3.11).
        return new PromptGovernanceReleaseGateService(
                contexaPromptGovernanceLifecycleLedgerService,
                promptGovernanceRegistryRepository,
                promptGovernanceChangeRecordRepository,
                promptGovernanceEvaluationRecordRepository,
                promptGovernanceReleaseApprovalRepository,
                promptGovernanceRollbackRecordRepository,
                promptGovernanceReleaseWorkflowRepository,
                promptGovernanceModelCompatibilityRepository,
                promptGovernanceBudgetProfileRepository,
                promptVersionCatalog.getIfAvailable(PromptVersionCatalog::none),
                versionedPrompts.getIfAvailable());
    }

    @Bean(name = "contexaPromptGovernanceEmpiricalEvalService")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptGovernanceRegistryRepository.class, PromptGovernanceEvaluationRecordRepository.class})
    public PromptGovernanceEmpiricalEvalService promptGovernanceEmpiricalEvalService(
            PromptGovernanceRegistryRepository promptGovernanceRegistryRepository,
            PromptGovernanceEvaluationRecordRepository promptGovernanceEvaluationRecordRepository) {
        return new PromptGovernanceEmpiricalEvalService(
                promptGovernanceRegistryRepository,
                promptGovernanceEvaluationRecordRepository);
    }

    /**
     * Plan 6-3: before the start of the prompt versions ({@link PromptVersionAutoConfiguration}, the last runner), which
     * retires the bundle rows this registration writes.
     */
    @Bean(name = "contexaPromptGovernanceRegistryBootstrapRunner")
    @ConditionalOnMissingBean(name = "contexaPromptGovernanceRegistryBootstrapRunner")
    @ConditionalOnBean(PromptGovernanceRegistryService.class)
    @Order(Ordered.LOWEST_PRECEDENCE - 100)
    public ApplicationRunner promptGovernanceRegistryBootstrapRunner(
            PromptGovernanceRegistryService contexaPromptGovernanceRegistryService,
            ObjectProvider<PromptGovernanceLifecycleLedgerService> promptGovernanceLifecycleLedgerService,
            ObjectProvider<PromptGovernanceModelCompatibilityRegistryService> promptGovernanceModelCompatibilityRegistryService) {
        // Registration of the platform prompts happens here only; the read paths no longer write. Each sync creates
        // missing rows and refreshes code-owned content, never the operational fields (version management PV-4).
        return args -> {
            contexaPromptGovernanceRegistryService.syncPlatformRegistry();
            promptGovernanceLifecycleLedgerService.ifAvailable(PromptGovernanceLifecycleLedgerService::syncPlatformLifecycleLedgers);
            promptGovernanceModelCompatibilityRegistryService.ifAvailable(PromptGovernanceModelCompatibilityRegistryService::syncPlatformRegistry);
        };
    }
}
