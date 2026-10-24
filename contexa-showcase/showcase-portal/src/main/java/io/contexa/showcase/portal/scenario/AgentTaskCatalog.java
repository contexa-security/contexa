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

/**
 * docs/agent A7-3: the business agent cases packaged under {@code agent-tasks/*.json} (A7-2c), each with the SHA-256 of
 * its canonical form as {@link ScenarioCatalog} computes it. They stay apart from the scenario catalog, so they are in no
 * measurement protocol and no benchmark; the visitor's agent group starts the ones the live settings name.
 */
public class AgentTaskCatalog {

    private final Map<String, ScenarioDefinition> tasks = new TreeMap<>();
    private final Map<String, String> hashes = new TreeMap<>();

    public AgentTaskCatalog(ObjectMapper json) throws IOException {
        Resource[] resources = new PathMatchingResourcePatternResolver().getResources("classpath*:agent-tasks/*.json");
        for (Resource resource : resources) {
            byte[] bytes;
            try (InputStream in = resource.getInputStream()) {
                bytes = in.readAllBytes();
            }
            ScenarioDefinition task = json.readValue(bytes, ScenarioDefinition.class);
            if (task.task() == null || task.agent() == null) {
                throw new IllegalStateException("Agent task " + task.key() + " has no agent or no work");
            }
            if (tasks.put(task.key(), task) != null) {
                throw new IllegalStateException("Duplicate agent task key " + task.key());
            }
            hashes.put(task.key(), ScenarioCatalog.hash(ScenarioCatalog.canonical(bytes)));
        }
    }

    public Optional<ScenarioDefinition> find(String key) {
        return Optional.ofNullable(key == null ? null : tasks.get(key));
    }

    public Collection<ScenarioDefinition> all() {
        return tasks.values();
    }

    /** The SHA-256 of a packaged agent case's canonical form ({@link ScenarioCatalog#CANONICAL_FORM}). */
    public Optional<String> sha256(String key) {
        return Optional.ofNullable(hashes.get(key));
    }
}
