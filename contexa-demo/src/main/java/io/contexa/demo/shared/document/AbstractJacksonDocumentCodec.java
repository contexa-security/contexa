package io.contexa.demo.shared.document;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public abstract class AbstractJacksonDocumentCodec implements DocumentCodec {

    private final ObjectMapper mapper;

    protected AbstractJacksonDocumentCodec(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public String write(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException failure) {
            throw new IllegalArgumentException("Document cannot be encoded", failure);
        }
    }

    public <T> T read(String value, Class<T> type) {
        try {
            return mapper.readValue(value, type);
        } catch (JsonProcessingException failure) {
            throw new IllegalStateException("Stored document is invalid", failure);
        }
    }

    public String hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public String hash(byte[] value) {
        try {
            return HexFormat.of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException(failure);
        }
    }
}
