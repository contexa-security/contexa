package io.contexa.showcase.portal.spec;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ExecutionSpecHasherTest {

    private static ExecutionSpec spec(Map<String, String> protection, String templateId, String mode) {
        return new ExecutionSpec("abc123", "0.1.0", mode, protection, "gpt-5-nano", "text-embedding-3-small",
                1024, "p".repeat(64), templateId, "r".repeat(64), null, "UTC");
    }

    @Test
    void hashIsStableAndIndependentOfMapInsertionOrder() {
        Map<String, String> first = new LinkedHashMap<>();
        first.put("/work/exports", "sync");
        first.put("/work/documents", "async");
        Map<String, String> second = new LinkedHashMap<>();
        second.put("/work/documents", "async");
        second.put("/work/exports", "sync");

        String hash = ExecutionSpecHasher.hash(spec(first, "tpl-1", "ENFORCE"));

        assertThat(hash).hasSize(64).matches("[0-9a-f]{64}");
        assertThat(ExecutionSpecHasher.hash(spec(second, "tpl-1", "ENFORCE"))).isEqualTo(hash);
    }

    @Test
    void anyMaterialChangeChangesTheHash() {
        Map<String, String> protection = Map.of("/work/exports", "sync");
        String base = ExecutionSpecHasher.hash(spec(protection, "tpl-1", "ENFORCE"));

        assertThat(ExecutionSpecHasher.hash(spec(protection, "tpl-2", "ENFORCE"))).isNotEqualTo(base);
        assertThat(ExecutionSpecHasher.hash(spec(protection, "tpl-1", "SHADOW"))).isNotEqualTo(base);
        assertThat(ExecutionSpecHasher.hash(spec(Map.of("/work/exports", "async"), "tpl-1", "ENFORCE")))
                .isNotEqualTo(base);
    }

    @Test
    void canonicalFormSortsEveryKeyAndUsesEmptyStringsForAbsentValues() {
        String json = ExecutionSpecHasher.canonicalJson(spec(Map.of("/b", "sync", "/a", "async"), null, "ENFORCE"));

        assertThat(json).startsWith("{\"chatModel\":\"gpt-5-nano\",\"codeCommit\":\"abc123\",\"contractVersion\":\"\"");
        assertThat(json).endsWith("\"templateId\":\"\",\"timeZone\":\"UTC\"}");
        assertThat(json).contains("\"endpointProtection\":{\"/a\":\"async\",\"/b\":\"sync\"}");
        assertThat(json).contains("\"templateId\":\"\"").contains("\"contractVersion\":\"\"");
    }
}
