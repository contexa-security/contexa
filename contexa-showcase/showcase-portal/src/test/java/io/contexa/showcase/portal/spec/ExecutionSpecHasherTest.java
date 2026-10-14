package io.contexa.showcase.portal.spec;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ExecutionSpecHasherTest {

    private static ExecutionSpec spec(Map<String, String> protection, String templateId, String mode) {
        return spec(protection, templateId, mode, null);
    }

    private static ExecutionSpec spec(Map<String, String> protection, String templateId, String mode,
                                      Map<String, Object> modelSettings) {
        return new ExecutionSpec("abc123", "0.1.0", mode, protection, "gpt-5-nano", "text-embedding-3-small",
                1024, "p".repeat(64), templateId, "r".repeat(64), null, "UTC", modelSettings);
    }

    private static Map<String, Object> settings(String effort, int limit) {
        Map<String, Object> layer = new LinkedHashMap<>();
        layer.put("reasoningEffort", effort);
        layer.put("verbosity", "low");
        layer.put("maxOutputTokens", limit);
        return Map.of("layer1Model", layer, "layer2Model", layer);
    }

    /**
     * The model settings change the verdicts (docs/showcase/데모-재설계.md R-13, R-20): two runs under different
     * reasoning effort or output limit must never be counted together. A specification recorded before the settings
     * were reported keeps the hash it had.
     */
    @Test
    void theModelSettingsArePartOfTheSpecification() {
        Map<String, String> protection = Map.of("/work/exports", "sync");
        String before = ExecutionSpecHasher.hash(spec(protection, "tpl-1", "ENFORCE"));
        String minimal = ExecutionSpecHasher.hash(spec(protection, "tpl-1", "ENFORCE", settings("minimal", 256)));

        assertThat(ExecutionSpecHasher.canonicalJson(spec(protection, "tpl-1", "ENFORCE")))
                .doesNotContain("modelSettings");
        assertThat(ExecutionSpecHasher.hash(spec(protection, "tpl-1", "ENFORCE", Map.of()))).isEqualTo(before);
        assertThat(minimal).isNotEqualTo(before);
        assertThat(ExecutionSpecHasher.hash(spec(protection, "tpl-1", "ENFORCE", settings("low", 256))))
                .isNotEqualTo(minimal);
        assertThat(ExecutionSpecHasher.hash(spec(protection, "tpl-1", "ENFORCE", settings("minimal", 1024))))
                .isNotEqualTo(minimal);
        assertThat(ExecutionSpecHasher.canonicalJson(spec(protection, "tpl-1", "ENFORCE", settings("low", 1024))))
                .contains("\"modelSettings\":{\"layer1Model\":{\"maxOutputTokens\":1024,\"reasoningEffort\":\"low\"");
    }

    /**
     * LU-6 (P3 extra 46): two measurements that differ only in the prompt bundle are two specifications and two
     * settings; a specification recorded before the bundle was reported keeps its hash.
     */
    @Test
    void thePromptBundleSeparatesSettingsAndLeavesOlderSpecificationsAsTheyWere() {
        ExecutionSpec before = spec(Map.of("/work/exports", "sync"), "tpl-1", "ENFORCE", settings("low", 2048));
        ExecutionSpec v19 = withBundle(before, "2026.10.13-v19.9");
        ExecutionSpec v20 = withBundle(before, "2026.10.14-v20.9");

        assertThat(ExecutionSpecHasher.canonicalJson(before)).doesNotContain("promptBundle");
        assertThat(ExecutionSpecHasher.canonicalJson(v20)).contains("\"promptBundle\":\"2026.10.14-v20.9\"");
        assertThat(ExecutionSpecHasher.hash(v20)).isNotEqualTo(ExecutionSpecHasher.hash(v19));
        assertThat(ExecutionSpecHasher.settingHash(v20, "v1")).isNotEqualTo(ExecutionSpecHasher.settingHash(v19, "v1"))
                .isNotEqualTo(ExecutionSpecHasher.settingHash(before, "v1"));
    }

    private static ExecutionSpec withBundle(ExecutionSpec spec, String bundle) {
        return new ExecutionSpec(spec.codeCommit(), spec.engineVersion(), spec.effectiveMode(),
                spec.endpointProtection(), spec.chatModel(), spec.embeddingModel(), spec.embeddingDimensions(),
                spec.promptHash(), spec.templateId(), spec.ruleVersion(), spec.contractVersion(), spec.timeZone(),
                spec.modelSettings(), bundle);
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

    /**
     * W5, V-13: one measurement protocol runs every protagonist from its own template, and a run with no model call
     * has no prompt (H-22); they share one measurement setting. The setting still separates other model settings and
     * templates learned under another version.
     */
    @Test
    void theMeasurementSettingIgnoresTheTemplateAndThePromptButNotTheirVersion() {
        Map<String, String> protection = Map.of("/work/exports", "sync");
        ExecutionSpec admin = spec(protection, "tpl-adm-a-1", "ENFORCE", settings("low", 2048));
        ExecutionSpec engineer = spec(protection, "tpl-eng-k-1", "ENFORCE", settings("low", 2048));
        ExecutionSpec noCall = new ExecutionSpec("abc123", "0.1.0", "ENFORCE", protection, "gpt-5-nano",
                "text-embedding-3-small", 1024, ExecutionSpec.NO_MODEL_CALL, null, "r".repeat(64), null, "UTC",
                settings("low", 2048));

        String setting = ExecutionSpecHasher.settingHash(admin, "v1");
        assertThat(ExecutionSpecHasher.hash(admin)).isNotEqualTo(ExecutionSpecHasher.hash(engineer));
        assertThat(ExecutionSpecHasher.settingHash(engineer, "v1")).isEqualTo(setting);
        assertThat(ExecutionSpecHasher.settingHash(noCall, "v1")).isEqualTo(setting).hasSize(64);
        assertThat(ExecutionSpecHasher.settingHash(admin, "v2")).as("templates learned under another version")
                .isNotEqualTo(setting);
        assertThat(ExecutionSpecHasher.settingHash(spec(protection, "tpl-adm-a-1", "ENFORCE", settings("medium", 2048)),
                "v1")).as("another reasoning effort").isNotEqualTo(setting);
    }
}
