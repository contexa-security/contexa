package io.contexa.showcase.portal.scenario;

import java.util.Locale;
import java.util.Map;

/**
 * docs/agent A6-D2: the names of the paths an agent case is measured on, as a measurement names them: the agent's
 * token for a person ({@code OAUTH2_DELEGATED}), its own client's token ({@code OAUTH2_AGENT}) and its own account's
 * session ({@code SESSION}).
 */
public final class AgentPaths {

    private static final Map<String, ScenarioDefinition.Sender> SENDERS = Map.of(
            "OAUTH2_DELEGATED", ScenarioDefinition.Sender.DELEGATED_AGENT,
            "OAUTH2_AGENT", ScenarioDefinition.Sender.AUTONOMOUS_AGENT,
            "SESSION", ScenarioDefinition.Sender.AGENT_SESSION);

    private AgentPaths() {
    }

    /**
     * The sender of a path.
     *
     * @throws IllegalArgumentException for an unknown path
     */
    public static ScenarioDefinition.Sender sender(String path) {
        ScenarioDefinition.Sender sender = path == null ? null : SENDERS.get(path.trim().toUpperCase(Locale.ROOT));
        if (sender == null) {
            throw new IllegalArgumentException("Unknown agent path " + path + "; one of " + SENDERS.keySet());
        }
        return sender;
    }

    /** The path of a sender, or null for the person. */
    public static String name(ScenarioDefinition.Sender sender) {
        return SENDERS.entrySet().stream().filter(entry -> entry.getValue() == sender).map(Map.Entry::getKey)
                .findFirst().orElse(null);
    }
}
