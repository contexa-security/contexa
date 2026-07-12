/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RestAuthenticationProviderTest {

    @Test
    void rejectsExpiredAccount() {
        UserDetailsService userDetailsService = mock(UserDetailsService.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        UserDetails userDetails = mock(UserDetails.class);
        when(userDetailsService.loadUserByUsername("expired")).thenReturn(userDetails);
        when(userDetails.isEnabled()).thenReturn(true);
        when(userDetails.isAccountNonLocked()).thenReturn(true);
        when(userDetails.isAccountNonExpired()).thenReturn(false);

        RestAuthenticationProvider provider = new RestAuthenticationProvider(
                userDetailsService, passwordEncoder, null);

        assertThatThrownBy(() -> provider.authenticate(
                RestAuthenticationToken.unauthenticated("expired", "secret")))
                .isInstanceOf(AccountExpiredException.class);
    }

    @Test
    void rejectsExternalAuthenticationOnlyAccount() {
        UserDetailsService userDetailsService = mock(UserDetailsService.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        UserDto account = UserDto.builder()
                .username("bridged")
                .password("encoded")
                .enabled(true)
                .externalAuthOnly(true)
                .build();
        UnifiedCustomUserDetails userDetails = new UnifiedCustomUserDetails(account, Set.of());
        when(userDetailsService.loadUserByUsername("bridged")).thenReturn(userDetails);
        when(passwordEncoder.matches("secret", "encoded")).thenReturn(true);

        RestAuthenticationProvider provider = new RestAuthenticationProvider(
                userDetailsService, passwordEncoder, null);

        assertThatThrownBy(() -> provider.authenticate(
                RestAuthenticationToken.unauthenticated("bridged", "secret")))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("External authentication only account");
    }
}
