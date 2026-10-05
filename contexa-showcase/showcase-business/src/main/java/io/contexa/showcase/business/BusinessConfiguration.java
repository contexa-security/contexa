package io.contexa.showcase.business;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.contexa.showcase.business.company.CompanyInitializer;
import io.contexa.showcase.business.company.CompanyRepository;
import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.context.JdbcBusinessContextLookup;
import io.contexa.showcase.business.internal.InternalApiGuardFilter;
import io.contexa.showcase.business.run.RunRegistry;
import io.contexa.showcase.business.work.BusinessController;
import io.contexa.showcase.business.work.BusinessOperations;
import io.contexa.showcase.business.work.BusinessRequestAttributes;
import io.contexa.showcase.business.work.BusinessService;
import io.contexa.showcase.business.work.WorkDatabase;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDate;

/**
 * Business part of a workload: the business database, the business API, the context lookup shared by controls C2
 * and D, the run registry and the management API guard. Imported only through {@link EnableShowcaseBusiness}.
 * <p>
 * Properties
 * <ul>
 *   <li>{@code showcase.control}: control name written into the business evidence (A/B, C1, C2, D)</li>
 *   <li>{@code showcase.work.datasource.url|username|password}: a separate pool for the business database; without
 *   it the application data source is the business database</li>
 *   <li>{@code showcase.company.generate-on-start}: generate the virtual company if the database has none</li>
 *   <li>{@code showcase.company.seed}, {@code showcase.company.anchor-date}: generation inputs</li>
 * </ul>
 */
public class BusinessConfiguration {

    public static final long DEFAULT_SEED = 20261005L;

    /** The workloads keep their own clock instead of a Clock bean, so the engine sees no extra bean. */
    private final Clock clock = Clock.systemUTC();

    @Bean(destroyMethod = "close")
    public WorkDatabase showcaseWorkDatabase(Environment environment, ObjectProvider<DataSource> applicationDataSource) {
        String url = environment.getProperty("showcase.work.datasource.url");
        if (url == null || url.isBlank()) {
            return new WorkDatabase(applicationDataSource.getObject(), null);
        }
        HikariConfig config = new HikariConfig();
        config.setPoolName("showcase-work");
        config.setJdbcUrl(url);
        config.setUsername(environment.getProperty("showcase.work.datasource.username"));
        config.setPassword(environment.getProperty("showcase.work.datasource.password"));
        config.setMaximumPoolSize(environment.getProperty("showcase.work.datasource.maximum-pool-size", Integer.class, 8));
        config.setMinimumIdle(environment.getProperty("showcase.work.datasource.minimum-idle", Integer.class, 2));
        config.setConnectionTimeout(3_000);
        HikariDataSource pool = new HikariDataSource(config);
        return new WorkDatabase(pool, pool);
    }

    @Bean
    public CompanyRepository companyRepository(WorkDatabase database) {
        return new CompanyRepository(database);
    }

    @Bean
    public BusinessContextLookup businessContextLookup(WorkDatabase database) {
        return new JdbcBusinessContextLookup(database);
    }

    @Bean
    public RunRegistry runRegistry(WorkDatabase database) {
        return new RunRegistry(database);
    }

    @Bean
    public BusinessService businessService(WorkDatabase database, Environment environment) {
        return new BusinessService(database, clock,
                environment.getProperty("showcase.business.stream.rows-per-tick", Integer.class, 8),
                Duration.ofMillis(environment.getProperty("showcase.business.stream.tick-millis", Long.class, 50L)));
    }

    @Bean
    public BusinessRequestAttributes businessRequestAttributes(WorkDatabase database) {
        return new BusinessRequestAttributes(database);
    }

    /** Control D registers a primary {@link BusinessOperations} with protected methods; the others use the service. */
    @Bean
    public BusinessController businessController(BusinessOperations operations, BusinessRequestAttributes attributes,
                                                 Environment environment) {
        return new BusinessController(operations, attributes, environment.getRequiredProperty("showcase.control"),
                clock);
    }

    @Bean
    public FilterRegistrationBean<InternalApiGuardFilter> showcaseInternalApiGuardFilter() {
        FilterRegistrationBean<InternalApiGuardFilter> registration = new FilterRegistrationBean<>(
                new InternalApiGuardFilter());
        registration.setName("showcaseInternalApiGuardFilter");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 2);
        return registration;
    }

    @Bean
    public CompanyGenerationRunner companyGenerationRunner(WorkDatabase database, CompanyRepository repository,
                                                           Environment environment) {
        boolean enabled = environment.getProperty("showcase.company.generate-on-start", Boolean.class, false);
        String anchor = environment.getProperty("showcase.company.anchor-date");
        CompanyInitializer initializer = new CompanyInitializer(database, repository,
                environment.getProperty("showcase.company.seed", Long.class, DEFAULT_SEED),
                anchor == null || anchor.isBlank() ? null : LocalDate.parse(anchor), clock);
        return new CompanyGenerationRunner(enabled ? initializer : null);
    }
}
