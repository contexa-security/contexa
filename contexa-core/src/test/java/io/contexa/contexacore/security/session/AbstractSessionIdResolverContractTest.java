package io.contexa.contexacore.security.session;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

abstract class AbstractSessionIdResolverContractTest {

    protected SessionIdResolver resolver;

    protected abstract SessionIdResolver createResolver();

    /** Must produce a session ID that the concrete resolver regards as active. */
    protected abstract String anActiveSessionId();

    @BeforeEach
    void setUpResolver() {
        resolver = createResolver();
    }

    @Test
    @DisplayName("isValid returns false for null session id")
    void isValid_null_returnsFalse() {
        assertThat(resolver.isValid(null)).isFalse();
    }

    @Test
    @DisplayName("isValid returns false for blank session id")
    void isValid_blank_returnsFalse() {
        assertThat(resolver.isValid("")).isFalse();
        assertThat(resolver.isValid("   ")).isFalse();
    }

    @Test
    @DisplayName("isValid returns false for non-UUID session id")
    void isValid_nonUuid_returnsFalse() {
        assertThat(resolver.isValid("not-a-uuid")).isFalse();
        assertThat(resolver.isValid("12345")).isFalse();
        assertThat(resolver.isValid("deadbeef")).isFalse();
    }

    @Test
    @DisplayName("isValid returns true for an active UUID-formatted session id")
    void isValid_activeUuid_returnsTrue() {
        String sid = anActiveSessionId();

        assertThat(resolver.isValid(sid))
                .as("active session id must be accepted in both modes")
                .isTrue();
    }
}
