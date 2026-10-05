package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/** Scenario definitions packaged with the portal under {@code scenarios/*.json}. */
public class ScenarioCatalog {

    private final Map<String, ScenarioDefinition> scenarios = new TreeMap<>();

    public ScenarioCatalog(ObjectMapper json) throws IOException {
        Resource[] resources = new PathMatchingResourcePatternResolver().getResources("classpath*:scenarios/*.json");
        for (Resource resource : resources) {
            try (InputStream in = resource.getInputStream()) {
                ScenarioDefinition scenario = json.readValue(in, ScenarioDefinition.class);
                if (scenarios.put(scenario.key(), scenario) != null) {
                    throw new IllegalStateException("Duplicate scenario key " + scenario.key());
                }
            }
        }
    }

    public Optional<ScenarioDefinition> find(String key) {
        return Optional.ofNullable(scenarios.get(key));
    }

    public Collection<ScenarioDefinition> all() {
        return scenarios.values();
    }
}
