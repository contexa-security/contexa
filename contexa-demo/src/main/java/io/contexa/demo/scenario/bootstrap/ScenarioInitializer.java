package io.contexa.demo.scenario.bootstrap;

import io.contexa.demo.scenario.codec.ScenarioCodec;
import io.contexa.demo.scenario.dto.ScenarioDeclaration;
import io.contexa.demo.scenario.service.ScenarioCatalog;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
@Profile("portal")
public class ScenarioInitializer implements ApplicationRunner {

    private final ScenarioCatalog catalog;
    private final ScenarioCodec codec;

    public ScenarioInitializer(ScenarioCatalog catalog, ScenarioCodec codec) {
        this.catalog = catalog;
        this.codec = codec;
    }

    public void run(ApplicationArguments args) throws Exception {
        var resources = new PathMatchingResourcePatternResolver().getResources("classpath*:lab/scenarios/*.json");
        if (resources.length == 0) {
            throw new IllegalStateException("Scenario declarations are missing");
        }
        for (var resource : resources) {
            try (var stream = resource.getInputStream()) {
                catalog.register(codec.read(new String(stream.readAllBytes(), StandardCharsets.UTF_8),
                        ScenarioDeclaration.class));
            }
        }
    }
}
