package io.contexa.demo.bootstrap.environment;

import io.contexa.demo.RuntimeLabApplication;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.system.ApplicationHome;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class LocalEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    private static final String LOCATION_PROPERTY = "lab.bootstrap.environment-location";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        Path file = localEnvironmentFile(environment);
        if (file != null) {
            environment.getPropertySources().addLast(new MapPropertySource("runtimeLabEnvironmentLocation",
                    Map.of(LOCATION_PROPERTY, file.toAbsolutePath().normalize().toUri() + "[.properties]")));
        }
    }

    @Override
    public int getOrder() {
        return ConfigDataEnvironmentPostProcessor.ORDER - 1;
    }

    private Path localEnvironmentFile(ConfigurableEnvironment environment) {
        String configuredFile = environment.getProperty("LAB_ENV_FILE");
        if (StringUtils.hasText(configuredFile)) {
            Path file = Path.of(configuredFile).toAbsolutePath().normalize();
            if (!Files.isRegularFile(file)) {
                throw new IllegalStateException("The Runtime Lab file configured by LAB_ENV_FILE does not exist");
            }
            return file;
        }

        Path directory = Path.of("").toAbsolutePath().normalize();
        for (Path file : new Path[] { directory.resolve("contexa-demo/.env"), directory.resolve(".env") }) {
            if (Files.isRegularFile(file)) {
                return file;
            }
        }

        Path location = new ApplicationHome(RuntimeLabApplication.class).getDir().toPath();
        for (Path candidate = location; candidate != null; candidate = candidate.getParent()) {
            if (candidate.getFileName() != null && "contexa-demo".equals(candidate.getFileName().toString())) {
                Path file = candidate.resolve(".env");
                return Files.isRegularFile(file) ? file : null;
            }
        }
        return null;
    }
}
