package io.contexa.showcase.portal.replay;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.InputStream;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Pair definitions packaged with the portal under {@code pairs/*.json}. Every scene must name a known scenario and a
 * step that scenario has, so a pair can never point at something that is not executed.
 */
public class PairCatalog {

    private final Map<String, PairDefinition> pairs = new TreeMap<>();

    public PairCatalog(ObjectMapper json, ScenarioCatalog scenarios) throws IOException {
        Resource[] resources = new PathMatchingResourcePatternResolver().getResources("classpath*:pairs/*.json");
        for (Resource resource : resources) {
            try (InputStream in = resource.getInputStream()) {
                PairDefinition pair = json.readValue(in, PairDefinition.class);
                validate(pair, scenarios);
                if (pairs.put(pair.key(), pair) != null) {
                    throw new IllegalStateException("Duplicate pair key " + pair.key());
                }
            }
        }
    }

    static void validate(PairDefinition pair, ScenarioCatalog scenarios) {
        for (PairDefinition.SceneKind kind : PairDefinition.SceneKind.values()) {
            PairDefinition.Scene scene = pair.scene(kind);
            ScenarioDefinition scenario = scenarios.find(scene.scenario()).orElseThrow(() ->
                    new IllegalStateException("Pair " + pair.key() + " names unknown scenario " + scene.scenario()));
            if (scene.featuredStep() < 1 || scene.featuredStep() > scenario.steps().size()) {
                throw new IllegalStateException("Pair " + pair.key() + " features step " + scene.featuredStep()
                        + " of scenario " + scenario.key() + ", which has " + scenario.steps().size());
            }
            if (!scene.sentence().containsKey("ko") || !scene.sentence().containsKey("en")) {
                throw new IllegalStateException("Pair " + pair.key() + " " + kind + " needs ko and en sentences");
            }
        }
        if (!pair.question().containsKey("ko") || !pair.question().containsKey("en")) {
            throw new IllegalStateException("Pair " + pair.key() + " needs ko and en questions");
        }
    }

    public Optional<PairDefinition> find(String key) {
        return Optional.ofNullable(pairs.get(key));
    }

    public List<PairDefinition> all() {
        return pairs.values().stream().sorted(Comparator.comparingInt(PairDefinition::order)).toList();
    }
}
