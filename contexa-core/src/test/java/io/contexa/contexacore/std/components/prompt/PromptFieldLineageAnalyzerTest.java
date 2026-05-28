package io.contexa.contexacore.std.components.prompt;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PromptFieldLineageAnalyzerTest {

    @Test
    void extractShouldStoreOnlyPromptFieldsAndIgnoreNarrativesAndBullets() {
        String prompt = """
                === CURRENT REQUEST AND EVENT ===
                User is requesting GET /admin/api/security-test/public/self-public-1779890243876 at 22:57.
                User: persona_fin_lead
                RequestPath: /admin/api/security-test/public/self-public-1779890243876
                AvailableFacts:
                - Actor identity is available.
                - ContextEvidenceLimitation: ROLE_SCOPE_PROFILE
                """;

        List<PromptFieldSnapshot> fields = PromptFieldLineageAnalyzer.extract(prompt);

        assertThat(fields).extracting(PromptFieldSnapshot::label)
                .containsExactly("User", "RequestPath", "AvailableFacts");
        assertThat(fields).extracting(PromptFieldSnapshot::label)
                .doesNotContain(
                        "User is requesting GET /admin/api/security-test/public/self-public-1779890243876 at 22",
                        "bullet.1",
                        "bullet.2");
        assertThat(fields).extracting(PromptFieldSnapshot::fieldKey)
                .doesNotContain(
                        "CURRENT_REQUEST_AND_EVENT.USER_IS_REQUESTING_GET_ADMIN_API_SECURITY_TEST_PUBLIC_SELF_PUBLIC_1779890243876_AT_22",
                        "CURRENT_REQUEST_AND_EVENT.BULLET_1",
                        "CURRENT_REQUEST_AND_EVENT.BULLET_2");
    }
}
