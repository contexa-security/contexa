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
package io.contexa.autoconfigure.core;

import io.contexa.autoconfigure.core.infra.CoreSchedulerLockAutoConfiguration;
import io.contexa.autoconfigure.iam.admin.PqaOfficialInspectionAutoConfiguration;
import io.contexa.autoconfigure.identity.IamSeedDataAutoConfiguration;
import io.contexa.autoconfigure.identity.IdentityOAuth2AutoConfiguration;
import io.contexa.contexacommon.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.AnnotatedGenericBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CoreContexaDataSourceIsolationContractTest {

    private static final String CONTEXA_DATA_SOURCE = "contexaDataSource";
    private static final String CONTEXA_JDBC_TEMPLATE = "contexaJdbcTemplate";
    private static final String CONTEXA_TRANSACTION_MANAGER = "contexaTransactionManager";
    private static final String CONTEXA_TRANSACTION_TEMPLATE = "contexaTransactionTemplate";

    @Test
    void contexaFallbackDefaultBeansAreExposedOnlyForContexaOwnedApplications() throws Exception {
        assertOwnedApplicationGuard("jdbcTemplate", DataSource.class);
        assertOwnedApplicationGuard("transactionTemplate", PlatformTransactionManager.class);
    }

    @Test
    void contexaRepositoryPostProcessorIsEnabledOnlyWhenConfigured() throws Exception {
        Method method = CoreDataAutoConfiguration.class.getDeclaredMethod(
                "contexaRepositoriesPostProcessor", Environment.class, ResourceLoader.class);
        ConditionalOnProperty conditional = method.getAnnotation(ConditionalOnProperty.class);

        assertThat(conditional).isNotNull();
        assertThat(conditional.prefix()).isEqualTo("contexa.jpa.repositories");
        assertThat(conditional.name()).containsExactly("enabled");
        assertThat(conditional.havingValue()).isEqualTo("true");
        assertThat(conditional.matchIfMissing()).isTrue();
    }

    @Test
    void contexaRepositoryPostProcessorDoesNothingWhenDisabled() {
        try (GenericApplicationContext context = new GenericApplicationContext()) {
            ContexaRepositoriesPostProcessor postProcessor = new ContexaRepositoriesPostProcessor(
                    new MockEnvironment().withProperty("contexa.jpa.repositories.enabled", "false"),
                    context);
            int before = context.getBeanDefinitionCount();

            postProcessor.postProcessBeanDefinitionRegistry(context);

            assertThat(context.getBeanDefinitionCount()).isEqualTo(before);
        }
    }

    @Test
    void contexaRepositoryPostProcessorRejectsApplicationScannedContexaRepository() {
        try (GenericApplicationContext context = new GenericApplicationContext()) {
            RootBeanDefinition repositoryBean = new RootBeanDefinition(Object.class);
            repositoryBean.getPropertyValues().add("repositoryInterface", UserRepository.class.getName());
            context.registerBeanDefinition("userRepository", repositoryBean);

            ContexaRepositoriesPostProcessor postProcessor = new ContexaRepositoriesPostProcessor(
                    new MockEnvironment(),
                    context);

            assertThatThrownBy(() -> postProcessor.postProcessBeanDefinitionRegistry(context))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Contexa repository packages must not be registered")
                    .hasMessageContaining(UserRepository.class.getName());
        }
    }

    @Test
    void contexaRepositoryPostProcessorRejectsConstructorRegisteredContexaRepository() {
        try (GenericApplicationContext context = new GenericApplicationContext()) {
            RootBeanDefinition repositoryBean = new RootBeanDefinition(Object.class);
            repositoryBean.getConstructorArgumentValues().addGenericArgumentValue(UserRepository.class);
            context.registerBeanDefinition("userRepository", repositoryBean);

            ContexaRepositoriesPostProcessor postProcessor = new ContexaRepositoriesPostProcessor(
                    new MockEnvironment(),
                    context);

            assertThatThrownBy(() -> postProcessor.postProcessBeanDefinitionRegistry(context))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining(UserRepository.class.getName());
        }
    }

    @Test
    void contexaRepositoryBeanNamesArePrefixedToAvoidUserRepositoryCollisions() {
        try (GenericApplicationContext context = new GenericApplicationContext()) {
            ContexaRepositoriesPostProcessor.ContexaRepositoryBeanNameGenerator generator =
                    new ContexaRepositoriesPostProcessor.ContexaRepositoryBeanNameGenerator();
            AnnotatedGenericBeanDefinition definition = new AnnotatedGenericBeanDefinition(UserRepository.class);

            assertThat(generator.generateBeanName(definition, context)).isEqualTo("contexaUserRepository");
        }
    }

    @Test
    void contexaAutoConfigurationInfrastructureParametersAreQualified() {
        assertInfrastructureParametersAreQualified(CoreDataAutoConfiguration.class);
        assertInfrastructureParametersAreQualified(CoreSchedulerLockAutoConfiguration.class);
        assertInfrastructureParametersAreQualified(IamSeedDataAutoConfiguration.class);
        assertInfrastructureParametersAreQualified(IdentityOAuth2AutoConfiguration.class);
        assertInfrastructureParametersAreQualified(PqaOfficialInspectionAutoConfiguration.class);
    }

    @Test
    void pqaQueryServiceUsesContexaJdbcTemplateExplicitly() {
        Method method = Stream.of(PqaOfficialInspectionAutoConfiguration.class.getDeclaredMethods())
                .filter(candidate -> candidate.getName().equals("pqaSealedEvidencePackageQueryService"))
                .findFirst()
                .orElseThrow();
        Parameter parameter = Stream.of(method.getParameters())
                .filter(candidate -> candidate.getType().equals(JdbcTemplate.class))
                .findFirst()
                .orElseThrow();

        assertThat(parameter.getAnnotation(Qualifier.class).value()).isEqualTo(CONTEXA_JDBC_TEMPLATE);
    }

    @Test
    void contexaOwnedDataSourceAutoConfigurationIsRegisteredBeforeCoreData() throws Exception {
        List<String> imports = Files.readAllLines(
                Path.of("src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports"),
                StandardCharsets.UTF_8);

        assertThat(imports)
                .contains("io.contexa.autoconfigure.core.ContexaOwnedDataSourceAutoConfiguration")
                .contains("io.contexa.autoconfigure.core.CoreDataAutoConfiguration");
        assertThat(imports.indexOf("io.contexa.autoconfigure.core.ContexaOwnedDataSourceAutoConfiguration"))
                .isLessThan(imports.indexOf("io.contexa.autoconfigure.core.CoreDataAutoConfiguration"));
    }

    @Test
    void coreServicesUseContexaTransactionManagerExplicitly() throws Exception {
        Path root = Path.of("..").toAbsolutePath().normalize();
        List<Path> sourceRoots = List.of(
                root.resolve("contexa-common/src/main/java"),
                root.resolve("contexa-core/src/main/java"),
                root.resolve("contexa-iam/src/main/java"),
                root.resolve("contexa-identity/src/main/java")
        );

        assertThat(findTransactionalViolations(sourceRoots)).isEmpty();
    }

    @Test
    void contexaPersistenceContextsDeclareContexaPersistenceUnit() throws Exception {
        Path root = Path.of("..").toAbsolutePath().normalize();
        List<Path> sourceRoots = List.of(
                root.resolve("contexa-common/src/main/java"),
                root.resolve("contexa-core/src/main/java"),
                root.resolve("contexa-iam/src/main/java"),
                root.resolve("contexa-identity/src/main/java"),
                Path.of("src/main/java")
        );

        assertThat(findPersistenceContextViolations(sourceRoots)).isEmpty();
    }

    private static void assertOwnedApplicationGuard(String methodName, Class<?>... parameterTypes) throws Exception {
        Method method = CoreDataAutoConfiguration.class.getDeclaredMethod(methodName, parameterTypes);
        ConditionalOnProperty conditional = method.getAnnotation(ConditionalOnProperty.class);

        assertThat(conditional).isNotNull();
        assertThat(conditional.prefix()).isEqualTo("contexa.datasource.isolation");
        assertThat(conditional.name()).containsExactly("contexa-owned-application");
        assertThat(conditional.havingValue()).isEqualTo("true");
    }

    private static void assertInfrastructureParametersAreQualified(Class<?> autoConfiguration) {
        List<String> violations = new ArrayList<>();
        for (Method method : autoConfiguration.getDeclaredMethods()) {
            if (method.isSynthetic() || method.getAnnotation(Bean.class) == null) {
                continue;
            }
            assertInfrastructureParametersAreQualified(autoConfiguration, method, violations);
        }
        for (Constructor<?> constructor : autoConfiguration.getDeclaredConstructors()) {
            assertInfrastructureParametersAreQualified(autoConfiguration, constructor, violations);
        }
        assertThat(violations).isEmpty();
    }

    private static void assertInfrastructureParametersAreQualified(
            Class<?> autoConfiguration,
            Executable executable,
            List<String> violations
    ) {
        for (Parameter parameter : executable.getParameters()) {
            if (parameter.getType().equals(DataSource.class)) {
                assertQualifier(autoConfiguration, executable, parameter, CONTEXA_DATA_SOURCE, violations);
            }
            if (parameter.getType().equals(JdbcTemplate.class)) {
                assertQualifier(autoConfiguration, executable, parameter, CONTEXA_JDBC_TEMPLATE, violations);
            }
            if (parameter.getType().equals(PlatformTransactionManager.class)) {
                assertQualifier(autoConfiguration, executable, parameter, CONTEXA_TRANSACTION_MANAGER, violations);
            }
            if (parameter.getType().equals(TransactionTemplate.class)) {
                assertQualifier(autoConfiguration, executable, parameter, CONTEXA_TRANSACTION_TEMPLATE, violations);
            }
        }
    }

    private static void assertQualifier(
            Class<?> autoConfiguration,
            Executable executable,
            Parameter parameter,
            String expected,
            List<String> violations
    ) {
        Qualifier qualifier = parameter.getAnnotation(Qualifier.class);
        if (qualifier == null || !expected.equals(qualifier.value())) {
            violations.add(autoConfiguration.getSimpleName() + "#" + executable.getName()
                    + " parameter " + parameter.getName() + " must use @" + Qualifier.class.getSimpleName()
                    + "(\"" + expected + "\")");
        }
    }

    private static List<String> findTransactionalViolations(List<Path> sourceRoots) throws IOException {
        List<String> violations = new ArrayList<>();
        for (Path sourceRoot : sourceRoots) {
            if (!Files.exists(sourceRoot)) {
                continue;
            }
            try (Stream<Path> paths = Files.walk(sourceRoot)) {
                for (Path path : paths
                        .filter(Files::isRegularFile)
                        .filter(file -> file.toString().endsWith(".java"))
                        .toList()) {
                    List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
                    for (int index = 0; index < lines.size(); index++) {
                        String line = lines.get(index);
                        if (line.contains("@Transactional")
                                && !line.contains("transactionManager = \"" + CONTEXA_TRANSACTION_MANAGER + "\"")) {
                            violations.add(path + ":" + (index + 1) + ": " + line.trim());
                        }
                    }
                }
            }
        }
        return violations;
    }

    private static List<String> findPersistenceContextViolations(List<Path> sourceRoots) throws IOException {
        List<String> violations = new ArrayList<>();
        for (Path sourceRoot : sourceRoots) {
            if (!Files.exists(sourceRoot)) {
                continue;
            }
            try (Stream<Path> paths = Files.walk(sourceRoot)) {
                for (Path path : paths
                        .filter(Files::isRegularFile)
                        .filter(file -> file.toString().endsWith(".java"))
                        .toList()) {
                    List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
                    for (int index = 0; index < lines.size(); index++) {
                        String line = lines.get(index);
                        if (line.contains("@PersistenceContext") && !line.contains("unitName = \"contexa\"")) {
                            violations.add(path + ":" + (index + 1) + ": " + line.trim());
                        }
                    }
                }
            }
        }
        return violations;
    }
}
