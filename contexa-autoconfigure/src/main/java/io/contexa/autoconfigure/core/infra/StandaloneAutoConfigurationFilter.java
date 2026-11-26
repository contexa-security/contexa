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
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.MethodMetadata;
import org.springframework.util.ClassUtils;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Keeps out of an application the auto-configurations that are Contexa's own in standalone mode, and the third-party ones
 * only Contexa's dependencies bring to an application that does not use them.
 *
 * <p>Contexa-owned ({@code io.contexa.*}) Redis and Kafka auto-configurations are excluded in standalone mode. Third-party
 * Redis and Kafka auto-configurations (Spring Boot, Redisson, Spring Kafka) are never excluded (R-9): Contexa brings none
 * of their libraries, so they are on the class path because the application put them there, and an application uses them
 * in more ways than its settings or its code can show (a session store, a cache). Contexa's own Redis branches stand on
 * the mode, not on the application's beans.</p>
 *
 * <p>Spring Boot's data source auto-configuration and Spring AI's pgvector store auto-configuration are excluded,
 * in every mode and whether Contexa is switched on or not, for an application that has no database of its own:
 * Contexa's dependencies bring them to its class path, and without a database they fail its startup.</p>
 *
 * <p>Spring Boot's Thymeleaf auto-configuration is excluded, in every mode and whether Contexa is switched on or not, for
 * an application that does not use Thymeleaf itself (R-9, F-04): Contexa's screens bring Thymeleaf to its class path, and
 * the view resolver Spring Boot then configures takes every view name before JSP. Contexa's screens have a template engine
 * of their own.</p>
 */
public class StandaloneAutoConfigurationFilter implements AutoConfigurationImportFilter, EnvironmentAware, BeanFactoryAware {

    private static final String MODE_PROPERTY = "contexa.infrastructure.mode";
    private static final String HTTP_SECURITY = "org.springframework.security.config.annotation.web.builders.HttpSecurity";

    private static final String REDIS_PATTERN = "redis";
    private static final String KAFKA_PATTERN = "kafka";
    private static final String CONTEXA_PACKAGE_PREFIX = "io.contexa.";
    private static final String CONTEXA_OWNED_DATASOURCE_AUTO_CONFIGURATION =
            "io.contexa.autoconfigure.core.ContexaOwnedDataSourceAutoConfiguration";

    /** Spring Boot's Thymeleaf auto-configuration, which Contexa's screens bring to an application's class path. */
    private static final Set<String> THYMELEAF_AUTO_CONFIGURATIONS = Set.of(
            "org.springframework.boot.autoconfigure.thymeleaf.ThymeleafAutoConfiguration",
            "org.springframework.boot.thymeleaf.autoconfigure.ThymeleafAutoConfiguration");

    /** Property names under which an application configures its own Thymeleaf. */
    private static final List<ConfigurationPropertyName> THYMELEAF_PROPERTIES =
            List.of(ConfigurationPropertyName.of("spring.thymeleaf"));

    /** What a class of an application that uses Thymeleaf names, as a class file names it: Thymeleaf, its layout dialect. */
    private static final List<String> THYMELEAF_SUPPORT = List.of("org/thymeleaf/", "nz/net/ultraq/thymeleaf/");

    /** A library only an application that uses Thymeleaf adds: Contexa does not bring it. */
    private static final String LAYOUT_DIALECT = "nz/net/ultraq/thymeleaf/layoutdialect/LayoutDialect.class";

    /** The templates Spring Boot's Thymeleaf reads by default: {@code spring.thymeleaf.prefix} and suffix, unset. */
    private static final String TEMPLATES = "classpath*:templates/**/*.html";
    private static final String TEMPLATES_DIRECTORY = "/templates/";
    /** Contexa's views: its screens under {@code contexa/}, and the name {@code contexa} itself. */
    private static final String CONTEXA_VIEWS = "contexa/";
    private static final String CONTEXA_VIEW = "contexa.html";

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

    @Override
    public boolean[] match(String[] autoConfigurationClasses, AutoConfigurationMetadata metadata) {
        boolean isStandalone = "standalone".equalsIgnoreCase(
                environment.getProperty(MODE_PROPERTY, "standalone"));
        boolean contexaPlatformActive = isContexaPlatformActive();
        Boolean hasDatabase = null;
        Boolean usesThymeleaf = null;

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

            if (THYMELEAF_AUTO_CONFIGURATIONS.contains(autoConfigurationClass)) {
                // Contexa's screens put Thymeleaf on the class path, and Spring Boot's Thymeleaf view resolver then takes every view name
                // before JSP. It is left out, whether Contexa is switched on or not, only for an application that does not use Thymeleaf.
                if (usesThymeleaf == null) {
                    usesThymeleaf = applicationUsesThymeleaf();
                }
                result[i] = usesThymeleaf;
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

    /**
     * Contexa's own Redis and Kafka auto-configurations, which the standalone mode does without. The third-party ones are the
     * application's: Contexa brings none of their libraries (R-9). Spring Boot's Kafka support stays as the application has it
     * without Contexa (RC grid start-host-redisson: 19 beans of the application gone), and so does its Redis support (F-06: an
     * application that used Redis without a connection key, through a session store or a cache, lost it).
     */
    private boolean isExcludedInStandalone(String autoConfigurationClass) {
        String lowerName = autoConfigurationClass.toLowerCase(Locale.ROOT);
        boolean redisRelated = lowerName.contains(REDIS_PATTERN);
        boolean kafkaRelated = lowerName.contains(KAFKA_PATTERN);
        return (redisRelated || kafkaRelated) && isContexaAutoConfiguration(autoConfigurationClass);
    }

    /**
     * Whether the application uses Thymeleaf itself: it configures it ({@code spring.thymeleaf}), it carries the layout dialect, it has
     * a template of its own where Spring Boot's Thymeleaf reads them (any but Contexa's views), or a class it registered or scanned names
     * Thymeleaf. Where the templates cannot be read, it is taken to use Thymeleaf: leaving its pages without their engine is worse than
     * leaving a JSP application as Contexa found it.
     */
    private boolean applicationUsesThymeleaf() {
        ClassLoader classLoader = applicationClassLoader();
        return hasAnyPropertyUnder(THYMELEAF_PROPERTIES)
                || classLoader.getResource(LAYOUT_DIALECT) != null
                || applicationTemplatePresent(classLoader)
                || !namedInCode(THYMELEAF_SUPPORT).isEmpty();
    }

    private static boolean applicationTemplatePresent(ClassLoader classLoader) {
        try {
            for (Resource template : new PathMatchingResourcePatternResolver(classLoader).getResources(TEMPLATES)) {
                String location = template.getURL().toString();
                int directory = location.lastIndexOf(TEMPLATES_DIRECTORY);
                String view = directory >= 0 ? location.substring(directory + TEMPLATES_DIRECTORY.length()) : location;
                if (!view.startsWith(CONTEXA_VIEWS) && !view.equals(CONTEXA_VIEW)) {
                    return true;
                }
            }
            return false;
        } catch (IOException | RuntimeException ex) {
            return true;
        }
    }

    private ClassLoader applicationClassLoader() {
        if (beanFactory instanceof ConfigurableListableBeanFactory listable && listable.getBeanClassLoader() != null) {
            return listable.getBeanClassLoader();
        }
        return getClass().getClassLoader();
    }

    /**
     * Which of the sought packages the classes the application registered or scanned name. Spring asks this filter before it reads
     * the beans of any configuration, so each class file is read as it stands, without loading the class: a type the class takes,
     * returns, builds or annotates with is named there by its package.
     */
    private Set<String> namedInCode(List<String> sought) {
        Set<String> named = new HashSet<>();
        if (!(beanFactory instanceof ConfigurableListableBeanFactory listable) || listable.getBeanClassLoader() == null) {
            return named;
        }
        ClassLoader classLoader = listable.getBeanClassLoader();
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
