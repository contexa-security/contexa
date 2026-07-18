package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;

/**
 * Serializes and deserializes CanonicalSecurityContext to/from JSON
 * for sealed evidence package persistence and replay.
 */
@Slf4j
public class CanonicalSecurityContextSerializer {

    private final ObjectMapper objectMapper;

    public CanonicalSecurityContextSerializer(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper")
                .copy()
                .findAndRegisterModules();
    }

    public String serialize(CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(context);
        } catch (JsonProcessingException e) {
            log.error("[SealedEvidence] Failed to serialize CanonicalSecurityContext", e);
            return null;
        }
    }

    public CanonicalSecurityContext deserialize(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(json, CanonicalSecurityContext.class);
        } catch (JsonProcessingException e) {
            log.error("[SealedEvidence] Failed to deserialize CanonicalSecurityContext", e);
            return null;
        }
    }
}