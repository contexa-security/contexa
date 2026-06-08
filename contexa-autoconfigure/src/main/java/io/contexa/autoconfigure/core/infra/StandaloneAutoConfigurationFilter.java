package io.contexa.autoconfigure.core.infra;

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import org.springframework.boot.autoconfigure.AutoConfigurationImportFilter;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

/**
 * Filters out Redis/Kafka/Redisson auto-configurations in standalone mode.
 * Uses pattern-based matching instead of hardcoded FQCNs,
 * so Spring Boot version changes or new auto-configurations are handled automatically.
 */
public class StandaloneAutoConfigurationFilter implements AutoConfigurationImportFilter, EnvironmentAware {

    private static final String MODE_PROPERTY = "contexa.infrastructure.mode";

    private static final String[] EXCLUDE_PATTERNS = {"redis", "kafka", "redisson"};
    private static final String CONTEXA_PACKAGE_PREFIX = "io.contexa.";

    private Environment environment;

    @Override
    public boolean[] match(String[] autoConfigurationClasses, AutoConfigurationMetadata metadata) {
        boolean isStandalone = "standalone".equalsIgnoreCase(
                environment.getProperty(MODE_PROPERTY, "standalone"));
        boolean contexaPlatformActive = isContexaPlatformActive();

        boolean[] result = new boolean[autoConfigurationClasses.length];
        for (int i = 0; i < autoConfigurationClasses.length; i++) {
            String autoConfigurationClass = autoConfigurationClasses[i];
            if (autoConfigurationClass == null) {
                result[i] = true;
                continue;
            }

            if (!contexaPlatformActive) {
                if (isContexaAutoConfiguration(autoConfigurationClass)) {
                    result[i] = false;
                } else if ("org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration".equals(autoConfigurationClass) ||
                           "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration".equals(autoConfigurationClass) ||
                           "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration".equals(autoConfigurationClass) ||
                           "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration".equals(autoConfigurationClass)) {
                    boolean hasUrl = environment.containsProperty("spring.datasource.url");
                    boolean hasEmbedded = EmbeddedDatabaseConnection.get(getClass().getClassLoader()) != EmbeddedDatabaseConnection.NONE;
                    result[i] = hasUrl || hasEmbedded;
                } else {
                    result[i] = true;
                }
                continue;
            }

            if (isStandalone) {
                String lowerName = autoConfigurationClass.toLowerCase();
                boolean excluded = false;
                for (String pattern : EXCLUDE_PATTERNS) {
                    if (lowerName.contains(pattern)) {
                        excluded = true;
                        break;
                    }
                }
                result[i] = !excluded;
            } else {
                result[i] = true;
            }
        }
        return result;
    }

    private boolean isContexaPlatformActive() {
        return environment != null && environment.containsProperty(AiSecurityImportSelector.PROP_MODE);
    }

    private boolean isContexaAutoConfiguration(String autoConfigurationClass) {
        return autoConfigurationClass.startsWith(CONTEXA_PACKAGE_PREFIX);
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }
}
