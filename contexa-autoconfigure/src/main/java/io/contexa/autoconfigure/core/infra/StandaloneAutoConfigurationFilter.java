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
package io.contexa.autoconfigure.core.infra;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigurationImportFilter;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
import org.springframework.boot.context.properties.source.ConfigurationPropertyName;
import org.springframework.boot.context.properties.source.ConfigurationPropertySource;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.context.properties.source.ConfigurationPropertyState;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.MethodMetadata;
import org.springframework.util.ClassUtils;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Filters Redis/Kafka/Redisson auto-configurations in standalone mode.
 * Uses pattern-based matching instead of hardcoded FQCNs,
 * so Spring Boot version changes or new auto-configurations are handled automatically.
 *
 * <p>Contexa-owned ({@code io.contexa.*}) infrastructure auto-configurations are always excluded in
 * standalone mode. Third-party infrastructure auto-configurations (Spring Boot, Redisson, Spring Kafka)
 * are excluded only when the host application has not configured that infrastructure itself, so a host
 * application that uses its own Redis or Kafka keeps its auto-configuration. It says so with a connection
 * property, or in its code: a class it registered or scanned names Spring's support for that infrastructure.</p>
 *
 * <p>Spring Boot's data source auto-configuration and Spring AI's pgvector store auto-configuration are excluded,
 * in every mode and whether Contexa is switched on or not, for an application that has no database of its own:
 * Contexa's dependencies bring them to its class path, and without a database they fail its startup.</p>
 */
public class StandaloneAutoConfigurationFilter implements AutoConfigurationImportFilter, EnvironmentAware, BeanFactoryAware {

    private static final String MODE_PROPERTY = "contexa.infrastructure.mode";
    private static final String HTTP_SECURITY = "org.springframework.security.config.annotation.web.builders.HttpSecurity";

    private static final String REDIS_PATTERN = "redis";
    private static final String KAFKA_PATTERN = "kafka";
    private static final String CONTEXA_PACKAGE_PREFIX = "io.contexa.";
    private static final String CONTEXA_OWNED_DATASOURCE_AUTO_CONFIGURATION =
            "io.contexa.autoconfigure.core.ContexaOwnedDataSourceAutoConfiguration";

    /**
     * Connection keys that show the host application configured its own Redis. Redisson keys are included
     * because the Redisson starter also provides the Redis connection factory used by Spring Data Redis.
     */
    private static final List<String> APPLICATION_REDIS_PROPERTIES = List.of(
            "spring.data.redis.host",
            "spring.data.redis.port",
            "spring.data.redis.url",
            "spring.data.redis.cluster.nodes",
            "spring.data.redis.sentinel.nodes",
            "spring.redis.host",
            "spring.redis.port",
            "spring.redis.url",
            "spring.redis.cluster.nodes",
            "spring.redis.sentinel.nodes",
            "spring.data.redis.redisson.config",
            "spring.data.redis.redisson.file",
            "spring.redis.redisson.config",
            "spring.redis.redisson.file");

    /**
     * Connection keys that show the host application configured its own Kafka cluster.
     */
    private static final List<String> APPLICATION_KAFKA_PROPERTIES = List.of(
            "spring.kafka.bootstrap-servers",
            "spring.kafka.producer.bootstrap-servers",
            "spring.kafka.consumer.bootstrap-servers",
            "spring.kafka.admin.bootstrap-servers",
            "spring.kafka.streams.bootstrap-servers");

    /** The packages of Spring's support for Redis, the Redisson starter's included, and for Kafka, as a class file names them. */
    private static final List<String> REDIS_SUPPORT = List.of("org/springframework/data/redis/", "org/redisson/");
    private static final List<String> KAFKA_SUPPORT = List.of("org/springframework/kafka/");

    /** What the Redis and the Kafka auto-configurations stand on: where it is not on the class path they keep out by themselves. */
    private static final String REDIS_OPERATIONS = "org/springframework/data/redis/core/RedisOperations.class";
    private static final String KAFKA_TEMPLATE = "org/springframework/kafka/core/KafkaTemplate.class";

    /** Property names under which an application says it has a database (the host's own, not Contexa's). */
    private static final List<ConfigurationPropertyName> DATABASE_PROPERTIES = Stream.of(
            "spring.datasource", "spring.jpa", "spring.data.jpa", "spring.flyway", "spring.liquibase", "spring.sql.init")
            .map(ConfigurationPropertyName::of).toList();

    /** Auto-configurations that fail the startup of an application that has no database. */
    private static final Set<String> FAILING_WITHOUT_A_DATABASE = Set.of(
            "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration",
            "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
            "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration");

    private Environment environment;
    private BeanFactory beanFactory;
    private Set<String> supportNamedInCode;

    @Override
    public boolean[] match(String[] autoConfigurationClasses, AutoConfigurationMetadata metadata) {
        boolean isStandalone = "standalone".equalsIgnoreCase(
                environment.getProperty(MODE_PROPERTY, "standalone"));
        boolean contexaPlatformActive = isContexaPlatformActive();
        Boolean hasDatabase = null;
        supportNamedInCode = null;

        boolean[] result = new boolean[autoConfigurationClasses.length];
        for (int i = 0; i < autoConfigurationClasses.length; i++) {
            String autoConfigurationClass = autoConfigurationClasses[i];
            if (autoConfigurationClass == null) {
                result[i] = true;
                continue;
            }

            if (FAILING_WITHOUT_A_DATABASE.contains(autoConfigurationClass)) {
                // Contexa's own dependencies put JDBC and JPA on the class path of an application that has no database, and its vector
                // store brings Spring AI's pgvector support. Spring Boot's data source auto-configuration then asks for a url, the pgvector
                // one for a JdbcTemplate, and the application does not start. They are left out, whether Contexa is switched on or not,
                // only for an application that has no database. Contexa uses neither: its own data source and vector store are separate.
                if (hasDatabase == null) {
                    hasDatabase = applicationHasDatabase();
                }
                result[i] = hasDatabase;
                continue;
            }

            if (!contexaPlatformActive) {
                if (isContexaOwnedDataSourceAutoConfiguration(autoConfigurationClass)) {
                    result[i] = hasContexaOwnedDataSource();
                } else if (isContexaAutoConfiguration(autoConfigurationClass)) {
                    result[i] = false;
                } else if (isBootSecurityAutoConfiguration(autoConfigurationClass) && !springSecurityPresent()) {
                    // The starter carries the OAuth2 libraries Contexa needs once it is on, not Spring Security's configuration
                    // support. An application that did not declare Spring Security has nothing for these to configure.
                    result[i] = false;
                } else {
                    result[i] = true;
                }
                continue;
            }

            result[i] = !isStandalone || !isExcludedInStandalone(autoConfigurationClass);
        }
        return result;
    }

    private boolean isExcludedInStandalone(String autoConfigurationClass) {
        String lowerName = autoConfigurationClass.toLowerCase(Locale.ROOT);
        boolean redisRelated = lowerName.contains(REDIS_PATTERN);
        boolean kafkaRelated = lowerName.contains(KAFKA_PATTERN);
        if (!redisRelated && !kafkaRelated) {
            return false;
        }
        if (isContexaAutoConfiguration(autoConfigurationClass)) {
            return true;
        }
        if (redisRelated && !applicationUses(APPLICATION_REDIS_PROPERTIES, REDIS_SUPPORT)) {
            return true;
        }
        return kafkaRelated && !applicationUses(APPLICATION_KAFKA_PROPERTIES, KAFKA_SUPPORT);
    }

    /**
     * Whether the application uses that infrastructure itself: it gives a connection property, or its code names Spring's support for
     * it. An application that builds its connection factories in code, or takes Spring Boot's template with the default address, gives
     * no property.
     */
    private boolean applicationUses(List<String> connectionProperties, List<String> support) {
        if (hasAnyApplicationProperty(connectionProperties)) {
            return true;
        }
        if (supportNamedInCode == null) {
            supportNamedInCode = supportNamedInCode();
        }
        return support.stream().anyMatch(supportNamedInCode::contains);
    }

    /**
     * Which of Spring's Redis and Kafka support the classes the application registered or scanned name. Spring asks this filter before it
     * reads the beans of any configuration, so each class file is read as it stands, without loading the class: a type the class takes,
     * returns, builds or annotates with is named there by its package. Nothing is read where the support is not on the class path.
     */
    private Set<String> supportNamedInCode() {
        Set<String> named = new HashSet<>();
        if (!(beanFactory instanceof ConfigurableListableBeanFactory listable) || listable.getBeanClassLoader() == null) {
            return named;
        }
        ClassLoader classLoader = listable.getBeanClassLoader();
        List<String> sought = new ArrayList<>();
        if (classLoader.getResource(REDIS_OPERATIONS) != null) {
            sought.addAll(REDIS_SUPPORT);
        }
        if (classLoader.getResource(KAFKA_TEMPLATE) != null) {
            sought.addAll(KAFKA_SUPPORT);
        }
        for (String beanName : listable.getBeanDefinitionNames()) {
            if (named.size() == sought.size()) {
                break;
            }
            if (listable.getBeanDefinition(beanName) instanceof AnnotatedBeanDefinition annotated) {
                String classFile = classFile(annotated.getMetadata().getClassName(), classLoader);
                sought.stream().filter(classFile::contains).forEach(named::add);
            }
        }
        return named;
    }

    private static String classFile(String className, ClassLoader classLoader) {
        String resource = ClassUtils.convertClassNameToResourcePath(className) + ClassUtils.CLASS_FILE_SUFFIX;
        try (InputStream in = classLoader.getResourceAsStream(resource)) {
            return in != null ? new String(in.readAllBytes(), StandardCharsets.ISO_8859_1) : "";
        } catch (IOException | RuntimeException ex) {
            // a class that cannot be read says nothing about what the application uses, and must not be what stops it
            return "";
        }
    }

    /** The application declared Spring Security: only that puts its configuration support on the class path. */
    boolean springSecurityPresent() {
        return ClassUtils.isPresent(HTTP_SECURITY, getClass().getClassLoader());
    }

    private static boolean isBootSecurityAutoConfiguration(String autoConfigurationClass) {
        return autoConfigurationClass.startsWith("org.springframework.boot.autoconfigure.security.")
                || autoConfigurationClass.startsWith("org.springframework.boot.actuate.autoconfigure.security.");
    }

    boolean embeddedDatabasePresent() {
        return EmbeddedDatabaseConnection.get(getClass().getClassLoader()) != EmbeddedDatabaseConnection.NONE;
    }

    /**
     * Whether the application has a database of its own: it says so with a url, a jndi name or any other data source, JPA, Flyway,
     * Liquibase or SQL initialization property, it carries an embedded database, or it declares a data source in its code. Contexa's
     * own database counts only where the application uses that one as well.
     */
    private boolean applicationHasDatabase() {
        return hasContexaOwnedDataSource() || hasAnyPropertyUnder(DATABASE_PROPERTIES)
                || embeddedDatabasePresent() || declaresDataSourceInCode();
    }

    /**
     * Whether any property source of the environment has a property under one of the names, in whatever form that source spells it:
     * an environment variable says {@code SPRING_DATASOURCE_URL}.
     */
    private boolean hasAnyPropertyUnder(List<ConfigurationPropertyName> names) {
        if (!(environment instanceof ConfigurableEnvironment configurable)) {
            return names.stream().anyMatch(name -> environment.containsProperty(name + ".url"));
        }
        for (ConfigurationPropertySource source : ConfigurationPropertySources.from(configurable.getPropertySources())) {
            for (ConfigurationPropertyName name : names) {
                ConfigurationPropertyState state = source.containsDescendantOf(name);
                // a source that cannot list its names is asked for the one name a database is rarely configured without
                if (state == ConfigurationPropertyState.PRESENT
                        || (state == ConfigurationPropertyState.UNKNOWN && source.getConfigurationProperty(name.append("url")) != null)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Whether a class the application registered or scanned declares a data source bean. Spring asks this filter before it reads the
     * beans of any configuration, so the declarations are read from the classes themselves, whatever condition they stand under.
     */
    private boolean declaresDataSourceInCode() {
        if (!(beanFactory instanceof ConfigurableListableBeanFactory listable)) {
            return false;
        }
        for (String beanName : listable.getBeanDefinitionNames()) {
            if (listable.getBeanDefinition(beanName) instanceof AnnotatedBeanDefinition annotated
                    && declaresDataSource(annotated.getMetadata(), listable.getBeanClassLoader())) {
                return true;
            }
        }
        return false;
    }

    private static boolean declaresDataSource(AnnotationMetadata metadata, ClassLoader classLoader) {
        Set<MethodMetadata> beanMethods;
        try {
            beanMethods = metadata.getAnnotatedMethods(Bean.class.getName());
        } catch (IllegalStateException | LinkageError ex) {
            // a class whose methods cannot be read is one Spring builds no bean from either
            return false;
        }
        for (MethodMetadata beanMethod : beanMethods) {
            if (isDataSource(beanMethod.getReturnTypeName(), classLoader)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDataSource(String typeName, ClassLoader classLoader) {
        try {
            return DataSource.class.isAssignableFrom(ClassUtils.forName(typeName, classLoader));
        } catch (ClassNotFoundException | LinkageError ex) {
            // a type that is not on the class path is not one this application builds
            return false;
        }
    }

    private boolean hasAnyApplicationProperty(List<String> propertyNames) {
        for (String propertyName : propertyNames) {
            if (environment.containsProperty(propertyName)
                    || environment.containsProperty(propertyName + "[0]")) {
                return true;
            }
        }
        return false;
    }

    private boolean isContexaPlatformActive() {
        return ContexaPlatformActivation.isActive(environment);
    }

    private boolean isContexaAutoConfiguration(String autoConfigurationClass) {
        return autoConfigurationClass.startsWith(CONTEXA_PACKAGE_PREFIX);
    }

    private boolean isContexaOwnedDataSourceAutoConfiguration(String autoConfigurationClass) {
        return CONTEXA_OWNED_DATASOURCE_AUTO_CONFIGURATION.equals(autoConfigurationClass);
    }

    private boolean hasContexaOwnedDataSource() {
        return environment != null
                && environment.containsProperty("contexa.datasource.url")
                && environment.getProperty(
                        "contexa.datasource.isolation.contexa-owned-application",
                        Boolean.class,
                        false);
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }
}
