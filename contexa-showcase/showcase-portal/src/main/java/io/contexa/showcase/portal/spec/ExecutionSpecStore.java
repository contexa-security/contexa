package io.contexa.showcase.portal.spec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Builds the execution specification of a run from what the run actually used (docs/showcase/실행명세.md): the engine
 * configuration control D reports, the rule controls' hash, the template, the system prompt hash observed in the run's
 * model calls and the build commit, and stores it once per distinct hash.
 */
public class ExecutionSpecStore {

    private static final TypeReference<Map<String, String>> PROTECTION = new TypeReference<>() {
    };
    private static final TypeReference<Map<String, Object>> SETTINGS = new TypeReference<>() {
    };
    private static final ObjectMapper SETTINGS_READER = new ObjectMapper();

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper json;

    public ExecutionSpecStore(NamedParameterJdbcTemplate jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public static ExecutionSpec build(JsonNode engine, JsonNode rules, String templateId, String promptHash,
                                      String contractVersion) {
        Map<String, String> protection = new LinkedHashMap<>();
        engine.path("endpointProtection").fields()
                .forEachRemaining(entry -> protection.put(entry.getKey(), entry.getValue().asText()));
        return new ExecutionSpec(
                required(engine, "codeCommit"),
                required(engine, "engineVersion"),
                engine.path("effectiveMode").asText(),
                protection,
                engine.path("chatModel").asText(),
                engine.path("embeddingModel").asText(),
                engine.path("embeddingDimensions").asInt(),
                promptHash,
                templateId,
                rules.path("sha256").asText(),
                contractVersion,
                engine.path("timeZone").asText(),
                modelSettings(engine));
    }

    /** A build fact control D must report; a specification is never recorded with a filled-in value (survey P1). */
    static String required(JsonNode engine, String field) {
        JsonNode value = engine.path(field);
        if (!value.isTextual() || value.asText().isBlank() || "unknown".equalsIgnoreCase(value.asText())) {
            throw new IllegalStateException("Control D did not report " + field + "; the execution specification is"
                    + " not recorded");
        }
        return value.asText();
    }

    /** Control D's model settings per layer as it reported them; null when it reported none. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> modelSettings(JsonNode engine) {
        Map<String, Object> settings = new LinkedHashMap<>();
        for (String layer : new String[]{"layer1Model", "layer2Model"}) {
            JsonNode node = engine.path(layer);
            if (node.isObject()) {
                settings.put(layer, SETTINGS_READER.convertValue(node, Map.class));
            }
        }
        return settings.isEmpty() ? null : settings;
    }

    /** Stores the specification if its hash is new and returns the hash. */
    public String record(ExecutionSpec spec) {
        String hash = ExecutionSpecHasher.hash(spec);
        jdbc.update("""
                        insert into execution_spec (spec_id, spec_hash, code_commit, engine_version, effective_mode,
                                                    endpoint_protection, chat_model, embedding_model,
                                                    embedding_dimensions, prompt_hash, template_id, rule_version,
                                                    contract_version, time_zone, model_settings)
                        values (:id, :hash, :commit, :engine, :mode, cast(:protection as jsonb), :chat, :embedding,
                                :dimensions, :prompt, :template, :rule, :contract, :zone,
                                cast(:modelSettings as jsonb))
                        on conflict (spec_hash) do nothing""",
                new MapSqlParameterSource("id", UUID.randomUUID()).addValue("hash", hash)
                        .addValue("commit", spec.codeCommit()).addValue("engine", spec.engineVersion())
                        .addValue("mode", spec.effectiveMode()).addValue("protection", write(spec.endpointProtection()))
                        .addValue("chat", spec.chatModel()).addValue("embedding", spec.embeddingModel())
                        .addValue("dimensions", spec.embeddingDimensions()).addValue("prompt", spec.promptHash())
                        .addValue("template", spec.templateId()).addValue("rule", spec.ruleVersion())
                        .addValue("contract", spec.contractVersion()).addValue("zone", spec.timeZone())
                        .addValue("modelSettings", spec.modelSettings() == null ? null : write(spec.modelSettings())));
        return hash;
    }

    /** The stored specification with the given hash, as it was recorded. */
    public Optional<ExecutionSpec> find(String specHash) {
        return jdbc.query("""
                        select code_commit, engine_version, effective_mode, endpoint_protection::text, chat_model,
                               embedding_model, embedding_dimensions, prompt_hash, template_id, rule_version,
                               contract_version, time_zone, model_settings::text
                          from execution_spec where spec_hash = :hash""",
                new MapSqlParameterSource("hash", specHash), (rs, n) -> new ExecutionSpec(rs.getString(1),
                        rs.getString(2), rs.getString(3), readProtection(rs.getString(4)), rs.getString(5),
                        rs.getString(6), rs.getInt(7), rs.getString(8), rs.getString(9), rs.getString(10),
                        rs.getString(11), rs.getString(12), readSettings(rs.getString(13))))
                .stream().findFirst();
    }

    private Map<String, Object> readSettings(String text) {
        if (text == null) {
            return null;
        }
        try {
            return json.readValue(text, SETTINGS);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable model settings", e);
        }
    }

    private Map<String, String> readProtection(String text) {
        try {
            return json.readValue(text, PROTECTION);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable endpoint protection", e);
        }
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unwritable execution specification", e);
        }
    }
}
