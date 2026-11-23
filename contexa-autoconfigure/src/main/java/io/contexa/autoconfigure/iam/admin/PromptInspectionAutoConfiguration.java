package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore;
import io.contexa.contexacore.autonomous.company.CompanyRecordsFactSourceVerifier;
import io.contexa.contexacore.autonomous.company.InMemoryCompanyRecordStore;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.inspection.PromptFactSourceVerifier;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionReinspection;
import io.contexa.contexacore.verification.inspection.PromptInspectionResultStore;
import io.contexa.contexacore.verification.inspection.PromptInspectionScheduler;
import io.contexa.contexacore.verification.inspection.PromptInspectionService;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import io.contexa.contexacore.verification.inspection.SourceTruthCheck;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCasePromotions;
import io.contexa.contexaiam.admin.promptquality.evidence.SealedEvidenceController;
import io.contexa.contexaiam.admin.promptquality.evidence.SealedEvidenceDetails;
import io.contexa.contexaiam.admin.promptquality.inspection.BundleTraceCheck;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionResultStore;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptReleaseLookup;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionApiController;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionConsole;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionPageController;
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
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.inspection.SealIntegrityCheck;

/**
 * OSS prompt inspection: the inspector, the result store in the OSS schema, the automatic round that inspects every
 * sealed package once on the scheduler's thread, the operator's re-inspection on its own executor, and the inspection
 * console (its read model and API), and the sealed evidence screen with the addresses of the sealed prompt screens it
 * joined. What an inspection found plays no part in how long a sealed package
 * is kept: the one retention of sealed packages is PqaSealedEvidenceAutoConfiguration's. Nothing here
 * runs on a decision thread. Enterprise keeps sealed packages in its own schema, so none of these beans are created
 * while Enterprise is enabled. The replay of sealed decisions is not wired here: switching the inspection off leaves it
 * and the prompt version trials on (SealedDecisionReplayAutoConfiguration).
 */
@AutoConfiguration(after = {PromptGovernanceAutoConfiguration.class, SealedEvidenceStoreAutoConfiguration.class,
        PqaSealedEvidenceAutoConfiguration.class})
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "false", matchIfMissing = true)
@ConditionalOnProperty(prefix = "contexa.prompt-inspection", name = "enabled", havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(PromptInspectionProperties.class)
public class PromptInspectionAutoConfiguration {

    /**
     * docs/agent OC-4: the source truth check reads Contexa's own company records and delegations again, unless the
     * application declares its own verifier of its sources.
     */
    @Bean(name = "contexaCompanyRecordsFactSourceVerifier")
    @ConditionalOnMissingBean(PromptFactSourceVerifier.class)
    public PromptFactSourceVerifier companyRecordsFactSourceVerifier(
            ObjectProvider<CompanyRecordStore> companyRecordStore,
            ObjectProvider<DelegationRegistry> delegationRegistry) {
        return new CompanyRecordsFactSourceVerifier(companyRecordStore.getIfAvailable(InMemoryCompanyRecordStore::new),
                delegationRegistry.getIfAvailable());
    }

    /**
     * The evidence audit (plan 2.1 of the prompt quality redesign): the core's seal integrity, the bundle trace right
     * after it and the source truth last. The trace reads the release registry when the prompt version management keeps
     * one; otherwise it says the trace cannot be checked.
     */
    @Bean(name = "contexaPromptInspector")
    @ConditionalOnMissingBean
    public PromptInspector promptInspector(
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
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
        // W6-7: the host's own records of the facts the sealed decision collected.
        checks.add(new SourceTruthCheck(sourceVerifier.getIfAvailable()));
        return new PromptInspector(checks, objectMapper);
    }

    @Bean(name = "contexaPromptInspectionResultStore")
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = {"contexaJdbcTemplate", "contexaTransactionManager"})
    public PromptInspectionResultStore promptInspectionResultStore(
            @Qualifier("contexaJdbcTemplate") JdbcOperations jdbcOperations,
            @Qualifier("contexaTransactionManager") PlatformTransactionManager transactionManager,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        return new JdbcPromptInspectionResultStore(jdbcOperations, new TransactionTemplate(transactionManager),
                objectMapper);
    }

    @Bean(name = "contexaPromptInspectionService")
    @ConditionalOnMissingBean
    @ConditionalOnBean({SealedEvidencePackageRepository.class, PromptInspectionResultStore.class})
    public PromptInspectionService promptInspectionService(
            PromptInspector contexaPromptInspector,
            SealedEvidencePackageRepository sealedEvidencePackageRepository,
            PromptInspectionResultStore contexaPromptInspectionResultStore) {
        return new PromptInspectionService(contexaPromptInspector, sealedEvidencePackageRepository,
                contexaPromptInspectionResultStore, Clock.systemUTC());
    }

    @Bean(name = "contexaPromptInspectionScheduler")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptInspectionService.class)
    public PromptInspectionScheduler promptInspectionScheduler(
            PromptInspectionService contexaPromptInspectionService,
            PromptInspectionProperties properties) {
        return new PromptInspectionScheduler(contexaPromptInspectionService, properties.getBatchSize(),
                properties.getSamplePercent());
    }

    @Bean(name = "contexaPromptInspectionReinspection")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptInspectionService.class)
    public PromptInspectionReinspection promptInspectionReinspection(
            PromptInspectionService contexaPromptInspectionService,
            PromptInspectionResultStore contexaPromptInspectionResultStore,
            PromptInspectionProperties properties) {
        return new PromptInspectionReinspection(contexaPromptInspectionService, contexaPromptInspectionResultStore,
                properties.getSamplePercent());
    }

    @Bean(name = "contexaPromptInspectionQueries")
    @ConditionalOnMissingBean
    @ConditionalOnBean(name = "contexaJdbcTemplate")
    public JdbcPromptInspectionQueries promptInspectionQueries(
            @Qualifier("contexaJdbcTemplate") JdbcOperations jdbcOperations) {
        return new JdbcPromptInspectionQueries(jdbcOperations);
    }

    @Bean(name = "contexaPromptInspectionConsole")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptInspectionService.class)
    public PromptInspectionConsole promptInspectionConsole(
            SealedEvidencePackageRepository sealedEvidencePackageRepository,
            PromptInspector contexaPromptInspector,
            PromptInspectionResultStore contexaPromptInspectionResultStore,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        return new PromptInspectionConsole(sealedEvidencePackageRepository, contexaPromptInspector,
                contexaPromptInspectionResultStore, objectMapper);
    }

    @Bean(name = "contexaPromptInspectionApiController")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptInspectionConsole.class, JdbcPromptInspectionQueries.class})
    public PromptInspectionApiController promptInspectionApiController(
            JdbcPromptInspectionQueries contexaPromptInspectionQueries,
            PromptInspectionConsole contexaPromptInspectionConsole,
            PromptInspectionReinspection contexaPromptInspectionReinspection) {
        return new PromptInspectionApiController(contexaPromptInspectionQueries, contexaPromptInspectionConsole,
                contexaPromptInspectionReinspection, Clock.systemUTC());
    }

    /** The addresses of the sealed prompt screens, which open the sealed evidence. */
    @Bean(name = "contexaPromptInspectionPageController")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptInspectionConsole.class)
    public PromptInspectionPageController promptInspectionPageController() {
        return new PromptInspectionPageController();
    }

    /**
     * Quality plan 3.7, 3.8: one sealed decision as the sealed evidence shows it, inspected again as it is read, with
     * the replays the audit log records of it.
     */
    @Bean(name = "contexaSealedEvidenceDetails")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptInspectionConsole.class)
    public SealedEvidenceDetails sealedEvidenceDetails(
            SealedEvidencePackageRepository sealedEvidencePackageRepository,
            PromptInspectionConsole contexaPromptInspectionConsole,
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        return new SealedEvidenceDetails(sealedEvidencePackageRepository, contexaPromptInspectionConsole,
                jdbcOperations::getIfAvailable, objectMapper);
    }

    /**
     * Quality plan 3.7, 3.8: the sealed evidence, the two sealed prompt screens joined; a sealed decision is made a
     * labelled case when the cases are here.
     */
    @Bean(name = "contexaSealedEvidenceController")
    @ConditionalOnMissingBean
    @ConditionalOnBean({SealedEvidenceDetails.class, JdbcPromptInspectionQueries.class})
    public SealedEvidenceController sealedEvidenceController(
            JdbcPromptInspectionQueries contexaPromptInspectionQueries,
            SealedEvidenceDetails contexaSealedEvidenceDetails,
            ObjectProvider<QualityCasePromotions> promotions, MessageSource messageSource,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        return new SealedEvidenceController(contexaPromptInspectionQueries, contexaSealedEvidenceDetails,
                promotions::getIfAvailable, messageSource, objectMapper, Clock.systemUTC());
    }
}
