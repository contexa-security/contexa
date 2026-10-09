package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W2-5: a case's published hash is computed over its canonical form (keys sorted, no whitespace, UTF-8), so it does
 * not depend on the file's indentation, key order or line ends, and anyone can recompute it from the definition.
 */
class ScenarioCatalogTest {

    @Test
    void theCanonicalFormSortsKeysAndDropsWhitespace() throws Exception {
        String canonical = ScenarioCatalog.canonical("""
                {
                  "b": [1, {"y": true, "x": null}],
                  "a": {"d": 2, "c": "관리자 A"}
                }
                """.getBytes(StandardCharsets.UTF_8));

        assertThat(canonical).isEqualTo("{\"a\":{\"c\":\"관리자 A\",\"d\":2},\"b\":[1,{\"x\":null,\"y\":true}]}");
    }

    @Test
    void aCasesHashDoesNotDependOnLineEndsOrIndentation() throws Exception {
        ScenarioCatalog catalog = new ScenarioCatalog(new ObjectMapper().findAndRegisterModules());
        byte[] file;
        try (InputStream in = ScenarioCatalogTest.class.getResourceAsStream("/scenarios/S12.json")) {
            file = in.readAllBytes();
        }
        String text = new String(file, StandardCharsets.UTF_8);
        String reformatted = text.replace("\r\n", "\n").replace("\n  ", "\n      ");

        String expected = ScenarioCatalog.hash(ScenarioCatalog.canonical(file));
        assertThat(catalog.sha256("S12")).hasValue(expected);
        assertThat(ScenarioCatalog.hash(ScenarioCatalog.canonical(reformatted.getBytes(StandardCharsets.UTF_8))))
                .isEqualTo(expected);
        assertThat(catalog.sha256("NONE")).isEmpty();
    }
}
