/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexacommon.security;

import io.contexa.contexacommon.domain.UserDto;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UnifiedCustomUserDetailsExternalOnlyTest {

    @Test
    void externalOnlySubjectIsInvalidForEveryUserDetailsBasedLocalProvider() {
        UserDto account = UserDto.builder()
                .username("bridge-subject")
                .enabled(true)
                .externalAuthOnly(true)
                .build();
        UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(account, Set.of());

        assertThat(details.isEnabled()).isFalse();
        assertThat(details.isCredentialsNonExpired()).isFalse();
        assertThatThrownBy(() -> LocalAccountStatusChecker.checkBeforeCredentials(details))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("External authentication only account");
    }
}
