package io.contexa.showcase.business;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** P5-SEC-02: a production application with a default or missing secret refuses to start. */
class ProductionSafetyTest {

    private static final String STRONG_PASSWORD = "a-long-random-password-2026";
    private static final String STRONG_KEY = randomKey();

    @Test
    void aDevelopmentStackKeepsItsLocalValues() {
        MockEnvironment development = new MockEnvironment().withProperty("spring.datasource.password", "showcase");

        assertThatCode(() -> ProductionSafety.verify(development, List.of("anything"))).doesNotThrowAnyException();
    }

    @Test
    void productionRefusesAWeakPassword() {
        for (String weak : new String[]{"", "short", "Showcase", "contexa1234!@#"}) {
            assertThatThrownBy(() -> ProductionSafety.verify(production(weak, STRONG_KEY), List.of()))
                    .as(weak).isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("spring.datasource.password")
                    .hasMessageNotContaining("signing-key");
        }
    }

    @Test
    void productionRefusesAMissingShortOrRepeatedSigningKey() {
        String zeros = Base64.getEncoder().encodeToString(new byte[32]);
        String repeated = Base64.getEncoder().encodeToString("abcdabcdabcdabcdabcdabcdabcdabcd".getBytes());
        String shortKey = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
        for (String weak : new String[]{"", "not base64 !", shortKey, zeros, repeated}) {
            assertThat(ProductionSafety.weakKey(weak)).as(weak).isTrue();
            assertThatThrownBy(() -> ProductionSafety.verify(production(STRONG_PASSWORD, weak), List.of()))
                    .as(weak).hasMessageContaining("showcase.internal.signing-key");
        }
        assertThat(ProductionSafety.weakKey(STRONG_KEY)).isFalse();
    }

    @Test
    void productionPassesWithStrongSecretsAndAddsTheApplicationsOwnProblemsWithoutPrintingValues() {
        MockEnvironment strong = production(STRONG_PASSWORD, STRONG_KEY);

        assertThatCode(() -> ProductionSafety.verify(strong, List.of())).doesNotThrowAnyException();
        assertThatThrownBy(() -> ProductionSafety.verify(strong, List.of("showcase.dev.forced-actions is on")))
                .hasMessageContaining("showcase.dev.forced-actions is on")
                .hasMessageNotContaining(STRONG_PASSWORD).hasMessageNotContaining(STRONG_KEY);
    }

    private static MockEnvironment production(String password, String key) {
        return new MockEnvironment().withProperty("showcase.production", "true")
                .withProperty("spring.datasource.password", password)
                .withProperty("showcase.internal.signing-key", key);
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
