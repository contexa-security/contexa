package io.contexa.demo.bootstrap.environment;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DatabasePasswordEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    private static final List<String> DATABASE_PASSWORD_PROPERTIES = List.of("spring.datasource.password",
            "lab.entry.store.password", "lab.evidence.password");

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String password = configuredPassword(environment);
        Map<String, Object> defaults = new LinkedHashMap<>();
        if (StringUtils.hasText(password) && !StringUtils.hasText(environment.getProperty("LAB_DB_PASSWORD"))) {
            defaults.put("LAB_DB_PASSWORD", password);
        }
        List<String> properties = new ArrayList<>(DATABASE_PASSWORD_PROPERTIES);
        if (environment.getProperty("contexa.enabled", Boolean.class, false)) {
            properties.add("contexa.datasource.password");
        }
        for (String property : properties) {
            if (!StringUtils.hasText(environment.getProperty(property)) && StringUtils.hasText(password)) {
                defaults.put(property, password);
            }
        }
        if (!defaults.isEmpty()) {
            environment.getPropertySources().addFirst(new MapPropertySource("runtimeLabDatabasePassword", defaults));
        }
        for (String property : properties) {
            requirePassword(environment, property);
        }
    }

    @Override
    public int getOrder() {
        return ConfigDataEnvironmentPostProcessor.ORDER + 1;
    }

    private String configuredPassword(ConfigurableEnvironment environment) {
        for (PropertySource<?> source : environment.getPropertySources()) {
            Object value = source.getProperty("LAB_DB_PASSWORD");
            if (value instanceof String candidate && StringUtils.hasText(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private void requirePassword(ConfigurableEnvironment environment, String property) {
        if (!StringUtils.hasText(environment.getProperty(property))) {
            throw new IllegalStateException("Runtime Lab database password is missing or blank for " + property
                    + ". Set LAB_DB_PASSWORD in contexa-demo/.env, LAB_ENV_FILE, or the process environment.");
        }
    }
}
