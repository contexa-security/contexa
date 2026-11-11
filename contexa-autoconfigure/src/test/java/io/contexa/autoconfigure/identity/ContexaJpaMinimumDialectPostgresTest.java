/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.identity;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.autoconfigure.core.ContexaOwnedDataSourceAutoConfiguration;
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.PersistenceUnitUtil;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Proxy;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.sql.DataSource;
import org.hibernate.Hibernate;
import org.hibernate.dialect.Dialect;
import org.hibernate.dialect.PostgreSQLDialect;
import org.hibernate.engine.jdbc.env.spi.ExtractedDatabaseMetaData;
import org.hibernate.engine.jdbc.env.spi.JdbcEnvironment;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.persister.entity.AbstractEntityPersister;
import org.hibernate.persister.entity.EntityPersister;
import org.hibernate.persister.entity.mutation.MutationCoordinator;
import org.hibernate.sql.model.MutationOperation;
import org.hibernate.sql.model.MutationOperationGroup;
import org.hibernate.sql.model.PreparableMutationOperation;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.Limit;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.core.RepositoryMetadata;
import org.springframework.data.repository.core.support.AbstractRepositoryMetadata;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Contexa's JPA settles its PostgreSQL dialect from the product name instead of the database's metadata, so it does
 * not reach its database while the application starts and Hibernate has no named dialect to warn about. The dialect
 * then targets the oldest version Hibernate supports instead of the version the database reports. Every repository
 * method of Contexa runs here on a real PostgreSQL twice, once on the dialect of the reported version as before and
 * once on the minimum one, and what reaches the driver (statements, binds) and what the method ends with are compared.
 */
class ContexaJpaMinimumDialectPostgresTest {

    private static final String DIALECT_OF_THE_REPORTED_VERSION =
            "contexa.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect";
    private static final Path REPORT = Path.of("build", "contexa-jpa-minimum-dialect.txt");
    private static final String SCHEMA = "META-INF/contexa/db/schema.sql";
    private static final String[] PRODUCT_NAME_SETTINGS = {
            "hibernate.boot.allow_jdbc_metadata_access",
            "jakarta.persistence.database-product-name",
            "hibernate.jdbc.use_scrollable_resultset"
    };
    private static final UUID SAMPLE_UUID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final LocalDateTime SAMPLE_TIME = LocalDateTime.of(2026, 1, 1, 0, 0);
    private static final Pattern MOMENT = Pattern.compile(
            "\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}(:\\d{2}(\\.\\d+)?)?([+-]\\d{2}(:\\d{2})?|Z)?");
    private static final Pattern RANDOM_UUID = Pattern.compile(
            "(?!00000000-0000-0000-0000-000000000001)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern FAILING_ROW = Pattern.compile("(?s)Detail: .*?(?=\\]|$)");
    private static final Pattern IDENTITY_HASH = Pattern.compile("@[0-9a-f]{4,}");
    private static final Pattern GENERATED_CLASS = Pattern.compile("\\$Proxy\\d+|\\$\\$SpringCGLIB\\$\\$\\d+|\\$HibernateProxy\\$\\w+");

    private static PostgresTestDatabase database;

    @BeforeAll
    static void installTheCanonicalSchemaWithItsSeeds() throws Exception {
        database = PostgresTestDatabase.empty();
        IamSeedDataAutoConfiguration.executeSchemaSql(database.dataSource(), SCHEMA,
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource(SCHEMA).getContentAsString(StandardCharsets.UTF_8)));
        List<String> seeds = new ArrayList<>(List.of(IamSeedDataAutoConfiguration.SEED_LOCATIONS));
        seeds.add(IamSeedDataAutoConfiguration.ACCOUNT_SEED_LOCATION);
        for (String seed : seeds) {
            IamSeedDataAutoConfiguration.seedPopulator(new ClassPathResource(seed)).execute(database.dataSource());
        }
    }

    @AfterAll
    static void drop() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    @DisplayName("Contexa's JPA settles its dialect without reaching its database and without the named-dialect warning")
    void theDialectIsSettledWithoutReachingTheDatabase() {
        Observation minimum = observe(false);

        assertThat(minimum.failure()).isNull();
        assertThat(minimum.bootConnections()).isZero();
        assertThat(minimum.hibernateLog()).noneMatch(line -> line.contains("HHH90000025"));
        assertThat(minimum.environment()).containsEntry("dialect version", "12.0");

        Observation reported = observe(false, DIALECT_OF_THE_REPORTED_VERSION);

        assertThat(reported.failure()).isNull();
        assertThat(reported.bootConnections()).isPositive();
        assertThat(reported.hibernateLog()).anyMatch(line -> line.contains("HHH90000025"));
        assertThat(reported.environment().get("dialect version")).startsWith(serverMajorVersion() + ".");
    }

    @Test
    @DisplayName("A Contexa database that takes the connection and never answers is neither reached nor waited for at start")
    void aDatabaseThatNeverAnswersIsNotWaitedForAtStart() throws Exception {
        try (SilentServer silent = SilentServer.start()) {
            long started = System.nanoTime();
            Observation minimum = observeAt(silent.url(), false, "contexa.datasource.hikari.connection-timeout-ms=3000");
            long startMs = Duration.ofNanos(System.nanoTime() - started).toMillis();

            assertThat(minimum.failure()).isNull();
            assertThat(minimum.bootConnections()).isZero();
            assertThat(silent.accepted()).isZero();
            assertThat(minimum.hibernateLog())
                    .noneMatch(line -> line.contains("HHH90000025") || line.contains("HHH000342"));
            System.out.println("[minimum dialect] start against a silent database took " + startMs + " ms");
        }
    }

    @Test
    @DisplayName("The application's own EntityManagerFactory still reads its database, next to Contexa's and on Contexa's pool")
    void theApplicationsOwnFactoryStillReadsItsDatabase() throws Exception {
        String serverVersion = serverMajorVersion() + ".";
        try (PostgresTestDatabase applicationDatabase = PostgresTestDatabase.empty()) {
            new ApplicationContextRunner()
                    .withUserConfiguration(Recording.class)
                    .withConfiguration(AutoConfigurations.of(DataSourceAutoConfiguration.class,
                            HibernateJpaAutoConfiguration.class, CoreDataAutoConfiguration.class))
                    .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                    .withPropertyValues(
                            "spring.datasource.url=" + applicationDatabase.dataSource().getJdbcUrl(),
                            "spring.datasource.username=" + applicationDatabase.dataSource().getUsername(),
                            "spring.datasource.password=" + applicationDatabase.dataSource().getPassword(),
                            "spring.jpa.hibernate.ddl-auto=none",
                            "contexa.datasource.url=" + database.dataSource().getJdbcUrl(),
                            "contexa.datasource.username=" + database.dataSource().getUsername(),
                            "contexa.datasource.password=" + database.dataSource().getPassword(),
                            "contexa.datasource.driver-class-name=org.postgresql.Driver")
                    .run(context -> {
                        assertThat(context).hasNotFailed();
                        assertThat(dialectVersion(context.getBean("entityManagerFactory", EntityManagerFactory.class)))
                                .startsWith(serverVersion);
                        assertThat(context.getBean("&entityManagerFactory", LocalContainerEntityManagerFactoryBean.class)
                                .getJpaPropertyMap()).doesNotContainKeys(PRODUCT_NAME_SETTINGS);
                        assertThat(dialectVersion(context.getBean("contexaEntityManagerFactory",
                                EntityManagerFactory.class))).isEqualTo("12.0");
                    });
        }
        // An application that Contexa owns runs its factory on Contexa's pool; that factory still reads the database.
        new ApplicationContextRunner()
                .withUserConfiguration(Recording.class)
                .withConfiguration(AutoConfigurations.of(ContexaOwnedDataSourceAutoConfiguration.class,
                        DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class,
                        CoreDataAutoConfiguration.class))
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                .withPropertyValues(
                        "spring.jpa.hibernate.ddl-auto=none",
                        "contexa.datasource.url=" + database.dataSource().getJdbcUrl(),
                        "contexa.datasource.username=" + database.dataSource().getUsername(),
                        "contexa.datasource.password=" + database.dataSource().getPassword(),
                        "contexa.datasource.driver-class-name=org.postgresql.Driver",
                        "contexa.datasource.isolation.contexa-owned-application=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(dialectVersion(context.getBean("entityManagerFactory", EntityManagerFactory.class)))
                            .startsWith(serverVersion);
                    assertThat(dialectVersion(context.getBean("contexaEntityManagerFactory",
                            EntityManagerFactory.class))).isEqualTo("12.0");
                });
    }

    @Test
    @DisplayName("Hibernate's schema validation still looks for Contexa's tables in the current schema first")
    void schemaValidationStillLooksInTheCurrentSchemaFirst() throws Exception {
        try (PostgresTestDatabase withAnotherSchema = PostgresTestDatabase.empty()) {
            IamSeedDataAutoConfiguration.executeSchemaSql(withAnotherSchema.dataSource(), SCHEMA,
                    IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                            new ClassPathResource(SCHEMA).getContentAsString(StandardCharsets.UTF_8)));
            // another schema of the same database holds a table of the same name whose column has another type
            withAnotherSchema.jdbcTemplate().execute("create schema zz_contexa_copy");
            withAnotherSchema.jdbcTemplate().execute(
                    "create table zz_contexa_copy.ctxa_admin_menu (id bigint primary key, name integer)");

            Observation validated = observeAt(withAnotherSchema.dataSource().getJdbcUrl(), false,
                    "contexa.jpa.hibernate.ddl-auto=validate");

            assertThat(validated.failure()).isNull();
            assertThat(validated.environment().get("dialect version")).startsWith(serverMajorVersion() + ".");
        }
    }

    @Test
    @DisplayName("Every Contexa repository method sends the same statements and binds and ends the same on the minimum dialect")
    void everyRepositoryMethodRunsTheSameOnTheMinimumDialect() throws IOException {
        Observation reported = observe(true, DIALECT_OF_THE_REPORTED_VERSION);
        Observation minimum = observe(true);
        assertThat(reported.failure()).isNull();
        assertThat(minimum.failure()).isNull();

        // What Hibernate takes from the database's metadata when it may read it; nothing else may differ.
        assertThat(differingKeys(reported.environment(), minimum.environment())).containsExactlyInAnyOrder(
                "dialect version", "dialect keywords", "current catalog", "current schema",
                "metadata: getGeneratedKeys", "metadata: scrollable results", "metadata: ref cursors",
                "metadata: DDL in transaction", "metadata: SQL state type", "metadata: sequences read");

        List<String> differences = new ArrayList<>();
        compare("entity", reported.entities(), minimum.entities(), differences);
        assertThat(minimum.calls().keySet()).containsExactlyElementsOf(reported.calls().keySet());
        Map<String, int[]> byFeature = new TreeMap<>();
        int statements = 0;
        for (Map.Entry<String, Call> entry : reported.calls().entrySet()) {
            Call before = entry.getValue();
            Call after = minimum.calls().get(entry.getKey());
            boolean same = before.equals(after);
            if (!same) {
                differences.add("call " + entry.getKey() + "\n  reported: " + before + "\n  minimum:  " + after);
            }
            statements += before.statements().stream().filter(line -> line.startsWith("prepare")
                    || line.startsWith("execute ")).count();
            for (String feature : reported.features().get(entry.getKey())) {
                int[] counts = byFeature.computeIfAbsent(feature, ignored -> new int[3]);
                counts[0]++;
                counts[same ? 1 : 2]++;
            }
        }
        writeReport(reported, minimum, byFeature, statements, differences);

        assertThat(reported.environment().get("dialect version")).startsWith(serverMajorVersion() + ".");
        assertThat(minimum.environment()).containsEntry("dialect version", "12.0");
        assertThat(reported.calls()).hasSizeGreaterThan(400);
        assertThat(statements).isGreaterThan(400);
        assertThat(differences).isEmpty();
    }

    private static String dialectVersion(EntityManagerFactory entityManagerFactory) {
        return String.valueOf(entityManagerFactory.unwrap(SessionFactoryImplementor.class)
                .getJdbcServices().getDialect().getVersion());
    }

    private static int serverMajorVersion() {
        Integer versionNumber = database.jdbcTemplate().queryForObject("show server_version_num", Integer.class);
        return versionNumber / 10000;
    }

    private static Observation observe(boolean exercise, String... properties) {
        return observeAt(database.dataSource().getJdbcUrl(), exercise, properties);
    }

    private static Observation observeAt(String url, boolean exercise, String... properties) {
        Logger hibernate = (Logger) LoggerFactory.getLogger("org.hibernate");
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        hibernate.addAppender(appender);
        AtomicReference<Observation> observed = new AtomicReference<>();
        try {
            new ApplicationContextRunner()
                    .withUserConfiguration(Recording.class)
                    .withConfiguration(AutoConfigurations.of(CoreDataAutoConfiguration.class))
                    .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                    .withPropertyValues(
                            "contexa.datasource.url=" + url,
                            "contexa.datasource.username=" + database.dataSource().getUsername(),
                            "contexa.datasource.password=" + database.dataSource().getPassword(),
                            "contexa.datasource.driver-class-name=org.postgresql.Driver")
                    .withPropertyValues(properties)
                    .run(context -> {
                        if (context.getStartupFailure() != null) {
                            observed.set(new Observation(context.getStartupFailure(), -1, List.of(), Map.of(),
                                    Map.of(), Map.of(), Map.of()));
                            return;
                        }
                        StatementRecorder recorder = context.getBean(StatementRecorder.class);
                        int bootConnections = recorder.connections();
                        EntityManagerFactory entityManagerFactory =
                                context.getBean("contexaEntityManagerFactory", EntityManagerFactory.class);
                        SessionFactoryImplementor sessionFactory =
                                entityManagerFactory.unwrap(SessionFactoryImplementor.class);
                        Map<String, String> environment = environment(sessionFactory, exercise);
                        Map<String, String> entities = exercise ? entities(sessionFactory) : Map.of();
                        Map<String, Call> calls = new LinkedHashMap<>();
                        Map<String, Set<String>> features = new LinkedHashMap<>();
                        if (exercise) {
                            exercise(context.getBeansOfType(Repository.class).values(), entityManagerFactory,
                                    new TransactionTemplate(context.getBean("contexaTransactionManager",
                                            PlatformTransactionManager.class)),
                                    recorder, calls, features);
                        }
                        observed.set(new Observation(null, bootConnections, List.of(), environment, entities,
                                calls, features));
                    });
        } finally {
            hibernate.detachAppender(appender);
        }
        List<String> log = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        Observation observation = observed.get();
        return new Observation(observation.failure(), observation.bootConnections(), log,
                observation.environment(), observation.entities(), observation.calls(), observation.features());
    }

    private static Map<String, String> environment(SessionFactoryImplementor sessionFactory, boolean withSequences) {
        Dialect dialect = sessionFactory.getJdbcServices().getDialect();
        JdbcEnvironment jdbc = sessionFactory.getJdbcServices().getJdbcEnvironment();
        ExtractedDatabaseMetaData metadata = jdbc.getExtractedDatabaseMetaData();
        Map<String, String> environment = new LinkedHashMap<>();
        environment.put("dialect", dialect.getClass().getSimpleName());
        environment.put("dialect version", String.valueOf(dialect.getVersion()));
        if (dialect instanceof PostgreSQLDialect postgres) {
            environment.put("driver kind", String.valueOf(postgres.getDriverKind()));
        }
        environment.put("dialect keywords", String.valueOf(dialect.getKeywords().size()));
        environment.put("name qualifier support", String.valueOf(jdbc.getNameQualifierSupport()));
        environment.put("current catalog", String.valueOf(jdbc.getCurrentCatalog()));
        environment.put("current schema", String.valueOf(jdbc.getCurrentSchema()));
        environment.put("metadata: getGeneratedKeys", String.valueOf(metadata.supportsGetGeneratedKeys()));
        environment.put("metadata: scrollable results", String.valueOf(metadata.supportsScrollableResults()));
        environment.put("metadata: batch updates", String.valueOf(metadata.supportsBatchUpdates()));
        environment.put("metadata: ref cursors", String.valueOf(metadata.supportsRefCursors()));
        environment.put("metadata: named parameters", String.valueOf(metadata.supportsNamedParameters()));
        environment.put("metadata: DDL in transaction", String.valueOf(metadata.supportsDataDefinitionInTransaction()));
        environment.put("metadata: DDL commits", String.valueOf(metadata.doesDataDefinitionCauseTransactionCommit()));
        environment.put("metadata: SQL state type", String.valueOf(metadata.getSqlStateType()));
        if (withSequences) {
            environment.put("metadata: sequences read", String.valueOf(metadata.getSequenceInformationList().size()));
        }
        environment.put("options: getGeneratedKeys", String.valueOf(
                sessionFactory.getSessionFactoryOptions().isGetGeneratedKeysEnabled()));
        environment.put("options: scrollable results", String.valueOf(
                sessionFactory.getSessionFactoryOptions().isScrollableResultSetsEnabled()));
        environment.put("options: JDBC batch size", String.valueOf(
                sessionFactory.getSessionFactoryOptions().getJdbcBatchSize()));
        environment.put("options: JDBC fetch size", String.valueOf(
                sessionFactory.getSessionFactoryOptions().getJdbcFetchSize()));
        return environment;
    }

    /** What Hibernate built for each entity at start: its identifier generator, insert delegate and static mutations. */
    private static Map<String, String> entities(SessionFactoryImplementor sessionFactory) {
        Map<String, String> entities = new TreeMap<>();
        sessionFactory.getMappingMetamodel().forEachEntityDescriptor(persister -> entities.put(
                persister.getEntityName(), describe(persister)));
        return entities;
    }

    private static String describe(EntityPersister persister) {
        StringBuilder description = new StringBuilder();
        description.append("generator=").append(persister.getGenerator() == null
                ? "none" : persister.getGenerator().getClass().getSimpleName());
        if (persister instanceof AbstractEntityPersister entityPersister) {
            description.append(" insertDelegate=").append(entityPersister.getInsertDelegate() == null
                    ? "none" : entityPersister.getInsertDelegate().getClass().getSimpleName());
        }
        description.append(" insert=").append(statements(persister.getInsertCoordinator()));
        description.append(" update=").append(statements(persister.getUpdateCoordinator()));
        description.append(" delete=").append(statements(persister.getDeleteCoordinator()));
        return description.toString();
    }

    private static String statements(MutationCoordinator coordinator) {
        MutationOperationGroup group = coordinator.getStaticMutationOperationGroup();
        if (group == null) {
            return "[dynamic]";
        }
        List<String> statements = new ArrayList<>();
        for (int index = 0; index < group.getNumberOfOperations(); index++) {
            MutationOperation operation = group.getOperation(index);
            statements.add(operation instanceof PreparableMutationOperation preparable
                    ? preparable.getSqlString() : operation.getClass().getSimpleName());
        }
        return statements.toString();
    }

    private static void exercise(Collection<Repository> repositoryBeans, EntityManagerFactory entityManagerFactory,
                                 TransactionTemplate transaction, StatementRecorder recorder,
                                 Map<String, Call> calls, Map<String, Set<String>> features) {
        PersistenceUnitUtil units = entityManagerFactory.getPersistenceUnitUtil();
        Set<Class<?>> entityTypes = entityManagerFactory.getMetamodel().getEntities().stream()
                .map(entity -> (Class<?>) entity.getJavaType())
                .collect(Collectors.toSet());
        Map<String, Object> repositories = new TreeMap<>();
        Map<String, Class<?>> repositoryTypes = new TreeMap<>();
        for (Object bean : repositoryBeans) {
            for (Class<?> type : AopProxyUtils.proxiedUserInterfaces(bean)) {
                if (Repository.class.isAssignableFrom(type) && type.getName().startsWith("io.contexa.")) {
                    repositories.put(type.getName(), bean);
                    repositoryTypes.put(type.getName(), type);
                }
            }
        }
        assertThat(repositories).hasSizeGreaterThan(50);
        for (Map.Entry<String, Object> repository : repositories.entrySet()) {
            Class<?> type = repositoryTypes.get(repository.getKey());
            RepositoryMetadata metadata = AbstractRepositoryMetadata.getMetadata(type);
            for (Method method : exercisedMethods(type)) {
                String key = type.getSimpleName() + "#" + method.getName() + Arrays.stream(method.getParameterTypes())
                        .map(Class::getSimpleName).collect(Collectors.joining(",", "(", ")"));
                Object[] arguments = arguments(method, metadata, entityTypes);
                boolean save = method.getName().startsWith("save");
                recorder.begin();
                String outcome;
                try {
                    outcome = transaction.execute(status -> {
                        status.setRollbackOnly();
                        try {
                            return "returned " + describe(method.invoke(repository.getValue(), arguments), units,
                                    entityTypes, save);
                        } catch (InvocationTargetException failure) {
                            return "threw " + describe(failure.getTargetException());
                        } catch (IllegalAccessException impossible) {
                            throw new IllegalStateException(impossible);
                        }
                    });
                } catch (RuntimeException transactionFailure) {
                    outcome = "transaction threw " + describe(transactionFailure);
                }
                calls.put(key, new Call(recorder.end(), outcome));
                features.put(key, features(method));
            }
        }
    }

    static List<Method> exercisedMethods(Class<?> repositoryType) {
        Map<String, Method> methods = new TreeMap<>();
        for (Method method : repositoryType.getMethods()) {
            if (method.isBridge() || method.isSynthetic() || Modifier.isStatic(method.getModifiers())) {
                continue;
            }
            if (!method.getDeclaringClass().getName().startsWith("io.contexa.") && !isExercisedBaseMethod(method)) {
                continue;
            }
            String signature = method.getName() + Arrays.toString(method.getParameterTypes());
            methods.putIfAbsent(signature, method);
        }
        return new ArrayList<>(methods.values());
    }

    private static boolean isExercisedBaseMethod(Method method) {
        Class<?>[] parameters = method.getParameterTypes();
        return switch (method.getName()) {
            case "findAll" -> parameters.length == 0
                    || (parameters.length == 1 && (parameters[0] == Pageable.class || parameters[0] == Sort.class));
            case "count" -> parameters.length == 0;
            case "findById", "existsById", "deleteById", "saveAndFlush" -> parameters.length == 1;
            case "findAllById" -> parameters.length == 1 && Iterable.class.isAssignableFrom(parameters[0]);
            default -> false;
        };
    }

    static Object[] arguments(Method method, RepositoryMetadata metadata, Set<Class<?>> entityTypes) {
        Class<?>[] types = method.getParameterTypes();
        Type[] genericTypes = method.getGenericParameterTypes();
        Object[] arguments = new Object[types.length];
        boolean save = method.getName().startsWith("save");
        for (int index = 0; index < types.length; index++) {
            arguments[index] = sample(types[index], genericTypes[index], metadata, entityTypes, save);
        }
        return arguments;
    }

    private static Object sample(Class<?> type, Type genericType, RepositoryMetadata metadata,
                                 Set<Class<?>> entityTypes, boolean save) {
        if (genericType instanceof TypeVariable<?> variable) {
            return "ID".equals(variable.getName())
                    ? sampleId(metadata.getIdType())
                    : (save ? newEntity(metadata.getDomainType()) : null);
        }
        Object simple = simpleSample(type);
        if (simple != null) {
            return simple;
        }
        if (Iterable.class.isAssignableFrom(type)) {
            Type element = genericType instanceof ParameterizedType parameterized
                    ? parameterized.getActualTypeArguments()[0] : Object.class;
            Object sample = element instanceof Class<?> elementType
                    ? sample(elementType, elementType, metadata, entityTypes, save)
                    : sample(Object.class, element, metadata, entityTypes, save);
            List<Object> values = new ArrayList<>();
            values.add(sample);
            return Set.class.isAssignableFrom(type) ? Set.copyOf(values) : values;
        }
        if (entityTypes.contains(type)) {
            return save ? newEntity(type) : null;
        }
        if (type == Map.class) {
            return Map.of();
        }
        if (type.isInterface() || Modifier.isAbstract(type.getModifiers())) {
            return null;
        }
        return filledInstance(type);
    }

    private static Object simpleSample(Class<?> type) {
        if (type == String.class) {
            return "fx4";
        }
        if (type == Long.class || type == long.class) {
            return 1L;
        }
        if (type == Integer.class || type == int.class) {
            return 1;
        }
        if (type == Short.class || type == short.class) {
            return (short) 1;
        }
        if (type == Double.class || type == double.class) {
            return 0.5d;
        }
        if (type == Float.class || type == float.class) {
            return 0.5f;
        }
        if (type == Boolean.class || type == boolean.class) {
            return Boolean.TRUE;
        }
        if (type == BigDecimal.class) {
            return BigDecimal.ONE;
        }
        if (type == BigInteger.class) {
            return BigInteger.ONE;
        }
        if (type == UUID.class) {
            return SAMPLE_UUID;
        }
        if (type == LocalDateTime.class) {
            return SAMPLE_TIME;
        }
        if (type == LocalDate.class) {
            return SAMPLE_TIME.toLocalDate();
        }
        if (type == LocalTime.class) {
            return SAMPLE_TIME.toLocalTime();
        }
        if (type == Instant.class) {
            return SAMPLE_TIME.toInstant(ZoneOffset.UTC);
        }
        if (type == OffsetDateTime.class) {
            return SAMPLE_TIME.atOffset(ZoneOffset.UTC);
        }
        if (type == ZonedDateTime.class) {
            return SAMPLE_TIME.atZone(ZoneOffset.UTC);
        }
        if (type == Timestamp.class) {
            return Timestamp.valueOf(SAMPLE_TIME);
        }
        if (type == Date.class) {
            return Date.from(SAMPLE_TIME.toInstant(ZoneOffset.UTC));
        }
        if (type == Duration.class) {
            return Duration.ofMinutes(5);
        }
        if (type == byte[].class) {
            return new byte[] {1, 2};
        }
        if (type.isEnum()) {
            return type.getEnumConstants()[0];
        }
        if (type == Pageable.class) {
            return PageRequest.of(0, 3);
        }
        if (type == Sort.class) {
            return Sort.unsorted();
        }
        if (type == Limit.class) {
            return Limit.of(3);
        }
        return null;
    }

    private static Object sampleId(Class<?> idType) {
        Object simple = simpleSample(idType);
        return simple != null ? simple : filledInstance(idType);
    }

    /** A new entity as its no-argument constructor leaves it, with an identifier the application would assign. */
    private static Object newEntity(Class<?> entityType) {
        Object entity = instantiate(entityType);
        if (entity == null) {
            return null;
        }
        for (Class<?> type = entityType; type != null && type != Object.class; type = type.getSuperclass()) {
            for (Field field : type.getDeclaredFields()) {
                boolean assignedId = field.isAnnotationPresent(Id.class) && !field.isAnnotationPresent(GeneratedValue.class);
                if (assignedId || field.isAnnotationPresent(EmbeddedId.class)) {
                    setIfNull(entity, field, sampleId(field.getType()));
                }
            }
        }
        return entity;
    }

    private static Object filledInstance(Class<?> type) {
        Object instance = instantiate(type);
        if (instance == null) {
            return null;
        }
        for (Class<?> current = type; current != null && current != Object.class; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (!Modifier.isStatic(field.getModifiers()) && !Modifier.isFinal(field.getModifiers())) {
                    setIfNull(instance, field, simpleSample(field.getType()));
                }
            }
        }
        return instance;
    }

    private static Object instantiate(Class<?> type) {
        try {
            Constructor<?> constructor = type.getDeclaredConstructor();
            constructor.setAccessible(true);
            return constructor.newInstance();
        } catch (ReflectiveOperationException | RuntimeException noDefaultConstructor) {
            return null;
        }
    }

    private static void setIfNull(Object target, Field field, Object value) {
        if (value == null || Modifier.isStatic(field.getModifiers())) {
            return;
        }
        try {
            field.setAccessible(true);
            if (field.get(target) == null) {
                field.set(target, value);
            }
        } catch (ReflectiveOperationException | RuntimeException notSettable) {
            // left as the constructor made it
        }
    }

    private static String describe(Object value, PersistenceUnitUtil units, Set<Class<?>> entityTypes, boolean save) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Optional<?> optional) {
            return optional.map(present -> "Optional[" + describe(present, units, entityTypes, save) + "]")
                    .orElse("Optional.empty");
        }
        if (value instanceof Page<?> page) {
            return "Page(total=" + page.getTotalElements() + ", " + describe(page.getContent(), units, entityTypes, save) + ")";
        }
        if (value instanceof Slice<?> slice) {
            return "Slice(next=" + slice.hasNext() + ", " + describe(slice.getContent(), units, entityTypes, save) + ")";
        }
        if (value instanceof Iterable<?> items) {
            List<String> described = new ArrayList<>();
            items.forEach(item -> described.add(describe(item, units, entityTypes, save)));
            return described.toString();
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, String> described = new TreeMap<>();
            map.forEach((key, item) -> described.put(String.valueOf(key), describe(item, units, entityTypes, save)));
            return described.toString();
        }
        if (value instanceof Object[] array) {
            return Arrays.stream(array).map(item -> describe(item, units, entityTypes, save)).toList().toString();
        }
        Class<?> type = Hibernate.getClass(value);
        if (entityTypes.contains(type)) {
            // an identity drawn in an earlier run stays drawn after its rollback, so a saved row is named by its type only
            return type.getSimpleName() + "#" + (save ? "saved" : String.valueOf(units.getIdentifier(value)));
        }
        if (value instanceof Number || value instanceof CharSequence || value instanceof Boolean
                || value instanceof Enum<?> || value instanceof TemporalAccessor || value instanceof Date
                || value instanceof UUID) {
            return String.valueOf(value);
        }
        return normalize(type.getSimpleName() + ":" + value);
    }

    private static String describe(Throwable failure) {
        List<String> chain = new ArrayList<>();
        for (Throwable current = failure; current != null && chain.size() < 6; current = current.getCause()) {
            chain.add(current.getClass().getName() + ": " + normalize(String.valueOf(current.getMessage())));
            if (current.getCause() == current) {
                break;
            }
        }
        return String.join(" <- ", chain);
    }

    private static String normalize(String text) {
        String normalized = FAILING_ROW.matcher(text).replaceAll("Detail: <row>");
        normalized = MOMENT.matcher(normalized).replaceAll("<moment>");
        normalized = RANDOM_UUID.matcher(normalized).replaceAll("<uuid>");
        normalized = IDENTITY_HASH.matcher(normalized).replaceAll("@<hash>");
        return GENERATED_CLASS.matcher(normalized).replaceAll("");
    }

    private static Set<String> features(Method method) {
        Set<String> features = new TreeSet<>();
        Query query = method.getAnnotation(Query.class);
        String text = query == null ? "" : query.value().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
        String name = method.getName();
        boolean contexaMethod = method.getDeclaringClass().getName().startsWith("io.contexa.");
        if (query != null) {
            features.add(query.nativeQuery() ? "native SQL" : "JPQL @Query");
        } else if (method.isDefault()) {
            features.add("default method (calls other queries)");
        } else if (!contexaMethod) {
            features.add("Spring Data base method");
        } else if (method.getDeclaringClass().getSimpleName().endsWith("Custom")) {
            features.add("Querydsl fragment");
        } else {
            features.add("derived query");
        }
        if (method.isAnnotationPresent(Modifying.class)) {
            features.add("@Modifying update/delete");
        }
        if (method.isAnnotationPresent(Lock.class)) {
            features.add("@Lock " + method.getAnnotation(Lock.class).value());
        }
        if (Arrays.asList(method.getParameterTypes()).contains(Pageable.class)) {
            features.add("Pageable (limit/offset + count)");
        }
        if (Arrays.asList(method.getParameterTypes()).contains(Limit.class)
                || name.matches("(find|read|get|query|search|stream|exists|count)(First|Top)\\d*.*")) {
            features.add("Top/First/Limit (fetch first)");
        }
        if (text.contains("ilike")) {
            features.add("ILIKE");
        }
        if (name.contains("IgnoreCase") || text.matches(".*\\b(lower|upper) ?\\(.*")) {
            features.add("case-insensitive lower()/upper()/IgnoreCase");
        }
        if (name.matches(".*(Containing|Like|StartingWith|EndingWith).*") || text.contains(" like ")) {
            features.add("LIKE");
        }
        if (text.contains("on conflict")) {
            features.add("ON CONFLICT upsert");
        }
        if (text.matches(".*(extract ?\\(|date_trunc|interval|cast ?\\().*")) {
            features.add("EXTRACT/INTERVAL/CAST");
        }
        if (text.contains("coalesce")) {
            features.add("COALESCE");
        }
        if (text.contains("||")) {
            features.add("string concatenation ||");
        }
        if (text.contains("join fetch")) {
            features.add("JOIN FETCH");
        }
        if (text.contains("group by") || text.matches(".*\\b(count|sum|avg|min|max) ?\\(.*")) {
            features.add("aggregates/GROUP BY");
        }
        if (text.contains("distinct") || name.contains("Distinct")) {
            features.add("DISTINCT");
        }
        if (text.contains("order by") || name.contains("OrderBy")) {
            features.add("ORDER BY");
        }
        if (text.matches(".*(exists ?\\(|in ?\\( ?select).*")) {
            features.add("subquery");
        }
        if (text.matches(".*\\b(current_timestamp|current_date|now ?\\(|local datetime|localdatetime).*")) {
            features.add("database time functions");
        }
        if (name.startsWith("save")) {
            features.add("entity insert/merge (save)");
        }
        if (name.startsWith("delete") || name.startsWith("remove")) {
            features.add("delete");
        }
        return features;
    }

    private static List<String> differingKeys(Map<String, String> before, Map<String, String> after) {
        assertThat(after.keySet()).containsExactlyElementsOf(before.keySet());
        return before.keySet().stream().filter(key -> !before.get(key).equals(after.get(key))).toList();
    }

    private static void compare(String kind, Map<String, String> before, Map<String, String> after,
                                List<String> differences) {
        assertThat(after.keySet()).as(kind).containsExactlyElementsOf(before.keySet());
        before.forEach((key, value) -> {
            if (!value.equals(after.get(key))) {
                differences.add(kind + " " + key + "\n  reported: " + value + "\n  minimum:  " + after.get(key));
            }
        });
    }

    private static void writeReport(Observation reported, Observation minimum, Map<String, int[]> byFeature,
                                    int statements, List<String> differences) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("Contexa JPA on the minimum dialect - " + reported.calls().size() + " repository calls, "
                + reported.entities().size() + " entities, " + statements + " statements prepared or run");
        lines.add("");
        lines.add("environment (reported | minimum)");
        reported.environment().forEach((key, value) -> lines.add(String.format(Locale.ROOT, "  %-32s %s | %s%s", key,
                value, minimum.environment().get(key), value.equals(minimum.environment().get(key)) ? "" : "   <- differs")));
        lines.add("");
        lines.add("calls by feature (calls / same / different)");
        byFeature.forEach((feature, counts) -> lines.add(String.format(Locale.ROOT, "  %-46s %4d %4d %4d",
                feature, counts[0], counts[1], counts[2])));
        lines.add("");
        lines.add("outcomes of the reported run");
        Map<String, Long> outcomes = reported.calls().values().stream()
                .collect(Collectors.groupingBy(call -> call.outcome().startsWith("returned") ? "returned"
                        : call.outcome().lines().findFirst().orElse("").replaceAll("^(threw|transaction threw) ([^:]+).*",
                                "$1 $2"), TreeMap::new, Collectors.counting()));
        outcomes.forEach((outcome, count) -> lines.add(String.format(Locale.ROOT, "  %5d %s", count, outcome)));
        lines.add("");
        lines.add("differences: " + differences.size());
        lines.addAll(differences);
        lines.add("");
        lines.add("calls");
        reported.calls().forEach((key, call) -> {
            lines.add(key + "  " + reported.features().get(key));
            call.statements().forEach(statement -> lines.add("    " + statement));
            lines.add("    => " + call.outcome());
        });
        lines.add("");
        lines.add("entities");
        reported.entities().forEach((key, value) -> lines.add("  " + key + " " + value));
        Files.createDirectories(REPORT.getParent());
        Files.write(REPORT, lines, StandardCharsets.UTF_8);
        System.out.println("[minimum dialect] report written to " + REPORT.toAbsolutePath());
    }

    record Observation(Throwable failure, int bootConnections, List<String> hibernateLog,
                       Map<String, String> environment, Map<String, String> entities,
                       Map<String, Call> calls, Map<String, Set<String>> features) {
    }

    record Call(List<String> statements, String outcome) {
    }

    @Configuration(proxyBeanMethods = false)
    static class Recording {

        @Bean
        static StatementRecorder contexaStatementRecorder() {
            return new StatementRecorder();
        }

        @Bean(name = "contexaJpaQueryFactory")
        JPAQueryFactory contexaJpaQueryFactory(
                @Qualifier("contexaEntityManagerFactory") EntityManagerFactory entityManagerFactory) {
            return new JPAQueryFactory(SharedEntityManagerCreator.createSharedEntityManager(entityManagerFactory));
        }
    }

    /**
     * Wraps Contexa's DataSource and writes down what reaches the driver on the thread being observed: each statement
     * prepared (with the way generated keys are asked for), each bound value with its JDBC setter and each execution.
     */
    static final class StatementRecorder implements BeanPostProcessor {

        private final AtomicInteger connections = new AtomicInteger();
        private final List<String> statements = new CopyOnWriteArrayList<>();
        private volatile Thread observed;

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) {
            if ("contexaDataSource".equals(beanName) && bean instanceof DataSource dataSource) {
                return dataSource(dataSource);
            }
            return bean;
        }

        int connections() {
            return connections.get();
        }

        void begin() {
            statements.clear();
            observed = Thread.currentThread();
        }

        List<String> end() {
            observed = null;
            List<String> recorded = List.copyOf(statements);
            statements.clear();
            return recorded;
        }

        private void note(String line) {
            if (Thread.currentThread() == observed) {
                statements.add(normalize(line));
            }
        }

        private DataSource dataSource(DataSource target) {
            return (DataSource) proxy(new Class<?>[] {DataSource.class, AutoCloseable.class}, target, (proxy, method, args) -> {
                if ("close".equals(method.getName()) && method.getParameterCount() == 0) {
                    if (target instanceof AutoCloseable closeable) {
                        closeable.close();
                    }
                    return null;
                }
                if ("getConnection".equals(method.getName())) {
                    connections.incrementAndGet();
                    return connection((Connection) call(target, method, args));
                }
                return call(target, method, args);
            });
        }

        private Connection connection(Connection target) {
            return (Connection) proxy(new Class<?>[] {Connection.class}, target, (proxy, method, args) -> {
                String name = method.getName();
                if ("prepareStatement".equals(name) || "prepareCall".equals(name)) {
                    note("prepare " + name + variant(args) + " | " + args[0]);
                    return statement(method.getReturnType(), call(target, method, args));
                }
                if ("createStatement".equals(name)) {
                    return statement(Statement.class, call(target, method, args));
                }
                return call(target, method, args);
            });
        }

        private Object statement(Class<?> type, Object target) {
            return proxy(new Class<?>[] {type}, target, (proxy, method, args) -> {
                String name = method.getName();
                Class<?>[] parameters = method.getParameterTypes();
                if (name.startsWith("set") && parameters.length >= 2 && parameters[0] == int.class) {
                    note("bind " + args[0] + " " + name + " " + value(args[1])
                            + (args.length > 2 ? " " + value(args[2]) : ""));
                } else if (name.startsWith("execute") || "addBatch".equals(name) || "getGeneratedKeys".equals(name)
                        || (name.startsWith("set") && parameters.length == 1)) {
                    note(name + (args != null && args.length > 0 ? " " + value(args[0]) : ""));
                }
                return call(target, method, args);
            });
        }

        private static String variant(Object[] args) {
            if (args.length == 1) {
                return "";
            }
            List<String> rest = new ArrayList<>();
            for (int index = 1; index < args.length; index++) {
                rest.add(value(args[index]));
            }
            return rest.toString();
        }

        private static String value(Object value) {
            if (value == null) {
                return "null";
            }
            if (value instanceof Object[] array) {
                return Arrays.deepToString(array);
            }
            if (value instanceof int[] ints) {
                return Arrays.toString(ints);
            }
            if (value instanceof byte[] bytes) {
                return "bytes" + Arrays.toString(bytes);
            }
            return value.getClass().getSimpleName() + ":" + value;
        }

        private static Object proxy(Class<?>[] interfaces, Object target, InvocationHandler handler) {
            return Proxy.newProxyInstance(StatementRecorder.class.getClassLoader(), interfaces, (proxy, method, args) -> {
                if ("equals".equals(method.getName()) && method.getParameterCount() == 1) {
                    return proxy == args[0];
                }
                if ("hashCode".equals(method.getName()) && method.getParameterCount() == 0) {
                    return System.identityHashCode(proxy);
                }
                return handler.invoke(proxy, method, args);
            });
        }

        private static Object call(Object target, Method method, Object[] args) throws Throwable {
            try {
                return method.invoke(target, args);
            } catch (InvocationTargetException failure) {
                throw failure.getTargetException();
            }
        }
    }

    /** A port that takes a connection and never answers, the way a database that froze or is cut off behaves. */
    static final class SilentServer implements AutoCloseable {

        private final ServerSocket socket;
        private final AtomicInteger accepted = new AtomicInteger();
        private final List<Socket> held = new CopyOnWriteArrayList<>();
        private final Thread acceptor;

        private SilentServer(ServerSocket socket) {
            this.socket = socket;
            this.acceptor = new Thread(this::accept, "silent-database");
            this.acceptor.setDaemon(true);
            this.acceptor.start();
        }

        static SilentServer start() throws IOException {
            return new SilentServer(new ServerSocket(0, 50, InetAddress.getLoopbackAddress()));
        }

        String url() {
            return "jdbc:postgresql://127.0.0.1:" + socket.getLocalPort() + "/contexa";
        }

        int accepted() {
            return accepted.get();
        }

        private void accept() {
            while (!socket.isClosed()) {
                try {
                    held.add(socket.accept());
                    accepted.incrementAndGet();
                } catch (IOException closed) {
                    return;
                }
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
            for (Socket connection : held) {
                connection.close();
            }
        }
    }
}
