package io.contexa.showcase.workload.contexa;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.context.collector.RoleScopeCollector;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurger;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.run.RunRegistry;
import io.contexa.showcase.business.work.BusinessService;
import io.contexa.showcase.business.work.WorkDatabase;
import io.contexa.showcase.workload.contexa.business.ContexaBusinessOperations;
import io.contexa.showcase.workload.contexa.context.BusinessFrictionProvider;
import io.contexa.showcase.workload.contexa.observation.AnalysisEventRecorder;
import io.contexa.showcase.workload.contexa.observation.DecisionRecords;
import io.contexa.showcase.workload.contexa.observation.EmbeddingUsageMeter;
import io.contexa.showcase.workload.contexa.observation.LlmUsageMeter;
import io.contexa.showcase.workload.contexa.observation.UsageLedger;
import io.contexa.showcase.workload.contexa.policy.EngineRbacSeeder;
import io.contexa.showcase.workload.contexa.principal.OrphanPrincipalSweeper;
import io.contexa.showcase.workload.contexa.principal.SharedAccountGuard;
import io.contexa.showcase.workload.contexa.principal.RunPrincipalService;
import io.contexa.showcase.workload.contexa.template.TemplateSnapshots;
import io.micrometer.observation.ObservationRegistry;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.time.Clock;
import io.contexa.showcase.business.ProductionSafety;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import java.util.ArrayList;
import java.util.List;

/**
 * Wiring of control D on top of the engine's public extension points: the protected business operations, the
 * engine RBAC seed, the business context provider, model usage and analysis event observers, run principals and
 * template snapshots (docs/showcase/ADR.md ADR-21 to ADR-24).
 */
@Configuration(proxyBeanMethods = false)
public class ContexaWorkloadConfiguration {

    private final Clock clock = Clock.systemUTC();

    @Bean
    @Primary
    public ContexaBusinessOperations contexaBusinessOperations(BusinessService businessService) {
        return new ContexaBusinessOperations(businessService);
    }

    @Bean
    public EngineRbacSeeder engineRbacSeeder(@Qualifier("contexaJdbcTemplate") JdbcTemplate engine,
                                             @Qualifier("contexaDataSource") DataSource engineDataSource,
                                             CustomDynamicAuthorizationManager authorizationManager) {
        return new EngineRbacSeeder(engine, new TransactionTemplate(new DataSourceTransactionManager(engineDataSource)),
                authorizationManager);
    }

    @Bean
    public RunPrincipalService runPrincipalService(UserRepository users,
                                                   @Qualifier("contexaJdbcTemplate") JdbcTemplate engine,
                                                   PasswordEncoder passwordEncoder, UserEngineStatePurger purger,
                                                   RunRegistry runs) {
        return new RunPrincipalService(users, engine, passwordEncoder, purger, runs);
    }

    /**
     * Refuses a production start with a default or missing secret or with the development-only forced decisions on
     * (deck p.37, P5-SEC-02, approval Q-23).
     */
    @Bean
    InitializingBean productionSafetyCheck(Environment environment) {
        return () -> {
            List<String> problems = new ArrayList<>();
            if (environment.getProperty("showcase.dev.forced-actions", Boolean.class, false)) {
                problems.add("showcase.dev.forced-actions is on");
            }
            if (ProductionSafety.weak(environment.getProperty("contexa.datasource.password"))) {
                problems.add("contexa.datasource.password is missing or weak");
            }
            if (ProductionSafety.blank(environment.getProperty("spring.ai.openai.api-key"))) {
                problems.add("spring.ai.openai.api-key is missing");
            }
            ProductionSafety.verify(environment, problems);
        };
    }

    @Bean
    public SharedAccountGuard sharedAccountGuard(@Qualifier("contexaJdbcTemplate") JdbcTemplate engine,
                                                 PasswordEncoder passwordEncoder) {
        return new SharedAccountGuard(engine, passwordEncoder);
    }

    @Bean
    public OrphanPrincipalSweeper orphanPrincipalSweeper(JdbcTemplate vectorDatabase,
                                                         @Qualifier("contexaJdbcTemplate") JdbcTemplate engine,
                                                         UserEngineStatePurger purger) {
        return new OrphanPrincipalSweeper(vectorDatabase, engine, purger, clock);
    }

    @Bean
    public TemplateSnapshots templateSnapshots(BaselineDataStore baselines, SecurityContextDataStore contexts,
                                               RoleScopeCollector roleScopes, UnifiedVectorService vectors,
                                               JdbcTemplate vectorDatabase, ObjectMapper objectMapper) {
        return new TemplateSnapshots(baselines, contexts, roleScopes, vectors, vectorDatabase, objectMapper, clock);
    }

    @Bean
    public BusinessFrictionProvider businessFrictionProvider(BusinessContextLookup lookup, WorkDatabase database) {
        return new BusinessFrictionProvider(lookup, database);
    }

    @Bean
    public UsageLedger usageLedger() {
        return new UsageLedger();
    }

    @Bean
    public LlmUsageMeter llmUsageMeter(UsageLedger ledger) {
        return new LlmUsageMeter(ledger, clock);
    }

    /**
     * Attaches the embedding meter to the observation registry itself. The engine's method authorization advisor is
     * created early with the whole engine graph, so the registry exists before Spring Boot attaches the registered
     * observation handlers and stays without any (docs/showcase approval Q-17). The meter is not a bean of the handler
     * type, so it is attached exactly once whether or not that is fixed.
     */
    @Bean
    public SmartInitializingSingleton embeddingUsageMeterRegistration(UsageLedger ledger,
                                                                      ObservationRegistry observationRegistry) {
        EmbeddingUsageMeter meter = new EmbeddingUsageMeter(ledger, clock);
        return () -> observationRegistry.observationConfig().observationHandler(meter);
    }

    @Bean
    public AnalysisEventRecorder analysisEventRecorder() {
        return new AnalysisEventRecorder(clock);
    }

    @Bean
    public DecisionRecords decisionRecords(@Qualifier("contexaJdbcTemplate") JdbcTemplate engine) {
        return new DecisionRecords(engine);
    }
}
