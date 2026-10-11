package io.contexa.contexaiam.testsupport;

import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceJpaLedgerWriter;
import jakarta.persistence.EntityManagerFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.util.Map;

/**
 * A Spring JPA context over a test DataSource holding only the prompt governance entities and repositories, so tests
 * exercise PromptGovernanceJpaLedgerWriter against a real schema. Hibernate validates the entities against the schema
 * when the context starts.
 */
public final class PromptGovernanceJpaTestContext implements AutoCloseable {

    private final AnnotationConfigApplicationContext context;

    private PromptGovernanceJpaTestContext(AnnotationConfigApplicationContext context) {
        this.context = context;
    }

    public static PromptGovernanceJpaTestContext open(DataSource dataSource) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.registerBean(DataSource.class, () -> dataSource);
        context.register(GovernanceJpaConfiguration.class);
        context.refresh();
        return new PromptGovernanceJpaTestContext(context);
    }

    public PromptGovernanceJpaLedgerWriter ledgerWriter() {
        return context.getBean(PromptGovernanceJpaLedgerWriter.class);
    }

    public TransactionTemplate transactionTemplate() {
        return new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
    }

    @Override
    public void close() {
        context.close();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableJpaRepositories(basePackageClasses = PromptGovernanceRegistryRepository.class)
    static class GovernanceJpaConfiguration {

        @Bean
        LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource dataSource) {
            LocalContainerEntityManagerFactoryBean factory = new LocalContainerEntityManagerFactoryBean();
            factory.setDataSource(dataSource);
            factory.setPackagesToScan("io.contexa.contexacore.domain.entity.prompt");
            factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
            factory.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "validate"));
            return factory;
        }

        @Bean
        PlatformTransactionManager transactionManager(EntityManagerFactory entityManagerFactory) {
            return new JpaTransactionManager(entityManagerFactory);
        }

        @Bean
        PromptGovernanceJpaLedgerWriter promptGovernanceJpaLedgerWriter(
                PromptGovernanceRegistryRepository registryRepository,
                PromptGovernanceChangeRecordRepository changeRepository,
                PromptGovernanceEvaluationRecordRepository evaluationRepository,
                PromptGovernanceReleaseApprovalRepository releaseApprovalRepository,
                PromptGovernanceReleaseWorkflowRepository releaseWorkflowRepository,
                PromptGovernanceRollbackRecordRepository rollbackRepository) {
            return new PromptGovernanceJpaLedgerWriter(
                    registryRepository,
                    changeRepository,
                    evaluationRepository,
                    releaseApprovalRepository,
                    releaseWorkflowRepository,
                    rollbackRepository);
        }
    }
}
