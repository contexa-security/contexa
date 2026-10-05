package io.contexa.showcase.portal.replay;

import java.util.List;
import java.util.Map;

/**
 * A representative pair (deck p.31, docs/showcase/P2-설계.md): an attack and a legitimate request that looks the
 * same, each played by a scenario. The pair holds the visitor wording; the scenarios hold what is executed.
 *
 * @param order    position in the quick start
 * @param question the one-sentence question of the first screen, per language (deck p.9)
 * @param scenes   the attack first, then the legitimate request
 */
public record PairDefinition(String key, int order, Map<String, String> question, List<Scene> scenes) {

    public enum SceneKind {
        ATTACK, LEGITIMATE
    }

    /**
     * @param scenario     key of the scenario that plays the scene
     * @param sentence     who, when, what in one sentence, per language (deck p.9)
     * @param featuredStep the step shown on screen 1 (1-based); the other steps are in the evidence drawer
     */
    public record Scene(SceneKind kind, String scenario, Map<String, String> sentence, int featuredStep) {
    }

    public Scene scene(SceneKind kind) {
        return scenes.stream().filter(scene -> scene.kind() == kind).findFirst()
                .orElseThrow(() -> new IllegalStateException("Pair " + key + " has no " + kind + " scene"));
    }
}
