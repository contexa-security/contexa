package io.contexa.showcase.portal.spec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * The R1 scoring contract packaged with the portal (deck p.33; docs/showcase/R1-채점계약-초안.md). Its version is the
 * SHA-256 of the contract as canonical JSON (keys sorted, no whitespace), so formatting never changes it and any value
 * does. Every run records this version in its execution specification ({@code contractVersion}, P2-BE-02).
 */
public class ScoringContract {

    static final String RESOURCE = "contract/r1-scoring-contract.json";
    private static final ObjectMapper CANONICAL = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private final JsonNode document;
    private final String version;

    public ScoringContract(ObjectMapper json) throws IOException {
        try (InputStream in = new ClassPathResource(RESOURCE).getInputStream()) {
            this.document = json.readTree(in);
        }
        this.version = sha256(canonical(document));
    }

    public JsonNode document() {
        return document;
    }

    public String version() {
        return version;
    }

    /** DRAFT until the values are approved and frozen. */
    public String status() {
        return document.path("status").asText("DRAFT");
    }

    static String canonical(JsonNode document) throws IOException {
        Object tree = CANONICAL.treeToValue(document, Object.class);
        return CANONICAL.writeValueAsString(tree);
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
