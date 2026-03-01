package io.contexa.autoconfigure.core.infra;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.Map;

/**
 * Sets standalone-specific properties when contexa.infrastructure.mode=standalone (default).
 * Auto-configuration filtering is handled by StandaloneAutoConfigurationFilter.
 */
public class StandaloneInfrastructurePostProcessor implements EnvironmentPostProcessor {

    private static final String MODE_PROPERTY = "contexa.infrastructure.mode";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String mode = environment.getProperty(MODE_PROPERTY, "standalone");
        if (!"standalone".equalsIgnoreCase(mode)) {
            return;
        }

        environment.getPropertySources().addFirst(
                new MapPropertySource("standaloneInfrastructureDefaults",
                        Map.of("contexa.cache.type", "LOCAL")));
    }
}
