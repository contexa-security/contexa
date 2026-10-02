package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class UserPromptEvidenceContractVerificationLabelTest {

    private static final String CANONICAL_CONTEXT = "{\"resource\":{\"verificationRequired\":true}}";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void currentPromptLabelProjectsVerificationRequiredField() throws Exception {
        Map<String, Object> field = verificationRequiredField("PromptQualityVerificationRequired: true");

        assertThat(field.get("promptValue")).isEqualTo("true");
        assertThat(field.get("projectionState")).isEqualTo("PRESENT");
    }

    @Test
    void legacyPromptLabelRemainsReadable() throws Exception {
        Map<String, Object> field = verificationRequiredField("VerificationRequired: true");

        assertThat(field.get("promptValue")).isEqualTo("true");
        assertThat(field.get("projectionState")).isEqualTo("PRESENT");
    }

    private Map<String, Object> verificationRequiredField(String finalUserPrompt) throws Exception {
        UserPromptEvidenceContract.Result result = UserPromptEvidenceContract.evaluate(
                objectMapper,
                finalUserPrompt,
                "{}",
                "{}",
                CANONICAL_CONTEXT,
                "{}",
                "{}",
                "{}",
                "{}");
        Map<String, Object> manifest = objectMapper.readValue(result.manifestJson(), new TypeReference<>() {
        });
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> fields = (List<Map<String, Object>>) manifest.get("fields");
        return fields.stream()
                .filter(field -> "verificationRequired".equals(field.get("fieldKey")))
                .findFirst()
                .orElseThrow();
    }
}
