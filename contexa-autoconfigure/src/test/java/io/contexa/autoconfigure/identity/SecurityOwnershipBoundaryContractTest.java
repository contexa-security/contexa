/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.autoconfigure.identity;

import io.contexa.autoconfigure.iam.IamSecurityCoreAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityOwnershipBoundaryContractTest {

    @Test
    void hostOwnedModeCannotMaterializeContexaAuthenticationInfrastructure() {
        assertContexaOwnedOnly(findMethod(
                IamSecurityCoreAutoConfiguration.class, "customAuthenticationProvider"));
        assertContexaOwnedOnly(IdentityOAuth2AutoConfiguration.class
                .getAnnotation(ConditionalOnProperty.class));
    }

    private Method findMethod(Class<?> type, String name) {
        return Arrays.stream(type.getDeclaredMethods())
                .filter(method -> method.getName().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private void assertContexaOwnedOnly(Method method) {
        assertContexaOwnedOnly(method.getAnnotation(ConditionalOnProperty.class));
    }

    private void assertContexaOwnedOnly(ConditionalOnProperty condition) {
        assertThat(condition).isNotNull();
        assertThat(condition.prefix()).isEqualTo("contexa.bridge");
        assertThat(condition.name()).containsExactly("ownership");
        assertThat(condition.havingValue()).isEqualTo("CONTEXA_OWNED");
        assertThat(condition.matchIfMissing()).isFalse();
    }
}
