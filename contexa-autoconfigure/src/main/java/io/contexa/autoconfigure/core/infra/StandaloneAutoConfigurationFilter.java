package io.contexa.autoconfigure.core.infra;

import org.springframework.boot.autoconfigure.AutoConfigurationImportFilter;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
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

    private Environment environment;

    @Override
    public boolean[] match(String[] autoConfigurationClasses, AutoConfigurationMetadata metadata) {
        boolean isStandalone = "standalone".equalsIgnoreCase(
                environment.getProperty(MODE_PROPERTY, "standalone"));

        boolean[] result = new boolean[autoConfigurationClasses.length];
        for (int i = 0; i < autoConfigurationClasses.length; i++) {
            if (isStandalone && autoConfigurationClasses[i] != null) {
                String lowerName = autoConfigurationClasses[i].toLowerCase();
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

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }
}
