package io.contexa.autoconfigure.core;

import io.contexa.autoconfigure.core.infra.CoreSchedulerLockAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class CoreContexaDataSourceIsolationContractTest {

    private static final String CONTEXA_DATA_SOURCE = "contexaDataSource";
    private static final String CONTEXA_JDBC_TEMPLATE = "contexaJdbcTemplate";
    private static final String CONTEXA_TRANSACTION_MANAGER = "contexaTransactionManager";

    @Test
    void contexaFallbackDefaultBeansAreExposedOnlyForContexaOwnedApplications() throws Exception {
        assertOwnedApplicationGuard("jdbcTemplate", DataSource.class);
        assertOwnedApplicationGuard("transactionTemplate", PlatformTransactionManager.class);
    }

    @Test
    void contexaAutoConfigurationInfrastructureParametersAreQualified() {
        assertInfrastructureParametersAreQualified(CoreDataAutoConfiguration.class);
        assertInfrastructureParametersAreQualified(CoreSchedulerLockAutoConfiguration.class);
    }

    @Test
    void coreAutoConfigurationSourceDoesNotUseUnqualifiedInfrastructureParameters() throws Exception {
        assertThat(findUnqualifiedInfrastructureParameterLines(List.of(Path.of("src/main/java")))).isEmpty();
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
            for (Parameter parameter : method.getParameters()) {
                if (parameter.getType().equals(DataSource.class)) {
                    assertQualifier(autoConfiguration, method, parameter, CONTEXA_DATA_SOURCE, violations);
                }
                if (parameter.getType().equals(JdbcTemplate.class)) {
                    assertQualifier(autoConfiguration, method, parameter, CONTEXA_JDBC_TEMPLATE, violations);
                }
                if (parameter.getType().equals(PlatformTransactionManager.class)) {
                    assertQualifier(autoConfiguration, method, parameter, CONTEXA_TRANSACTION_MANAGER, violations);
                }
            }
        }
        assertThat(violations).isEmpty();
    }

    private static void assertQualifier(
            Class<?> autoConfiguration,
            Method method,
            Parameter parameter,
            String expected,
            List<String> violations
    ) {
        Qualifier qualifier = parameter.getAnnotation(Qualifier.class);
        if (qualifier == null || !expected.equals(qualifier.value())) {
            violations.add(autoConfiguration.getSimpleName() + "#" + method.getName()
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

    private static List<String> findUnqualifiedInfrastructureParameterLines(List<Path> sourceRoots) throws IOException {
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
                        if (containsInfrastructureParameter(line) && !isAllowedInfrastructureLine(line)) {
                            violations.add(path + ":" + (index + 1) + ": " + line.trim());
                        }
                    }
                }
            }
        }
        return violations;
    }

    private static boolean containsInfrastructureParameter(String line) {
        return line.contains("JdbcTemplate jdbcTemplate")
                || line.contains("DataSource dataSource")
                || line.contains("PlatformTransactionManager platformTransactionManager")
                || line.contains("TransactionTemplate transactionTemplate");
    }

    private static boolean isAllowedInfrastructureLine(String line) {
        return line.contains("@Qualifier(\"contexa")
                || line.contains("new JdbcTemplate(dataSource)")
                || line.contains("private final")
                || line.contains("private void initializeAuthorizationServerSchema")
                || line.contains("public TransactionTemplate transactionTemplate");
    }
}
