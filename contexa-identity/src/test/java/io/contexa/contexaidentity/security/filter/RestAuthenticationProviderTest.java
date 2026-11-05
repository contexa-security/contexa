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
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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

    @Test
    void anUnknownUserAndAWrongPasswordFailAlike() {
        UserDetailsService userDetailsService = mock(UserDetailsService.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        when(passwordEncoder.encode(any())).thenReturn("decoy");
        when(userDetailsService.loadUserByUsername("ghost"))
                .thenThrow(new UsernameNotFoundException("User not found: ghost"));
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(account("alice", true, false));
        RestAuthenticationProvider provider = new RestAuthenticationProvider(
                userDetailsService, passwordEncoder, null);

        assertThatThrownBy(() -> provider.authenticate(
                RestAuthenticationToken.unauthenticated("ghost", "secret")))
                .isExactlyInstanceOf(BadCredentialsException.class)
                .hasMessage("Invalid username or password.");
        assertThatThrownBy(() -> provider.authenticate(
                RestAuthenticationToken.unauthenticated("alice", "wrong")))
                .isExactlyInstanceOf(BadCredentialsException.class)
                .hasMessage("Invalid username or password.");
    }

    @Test
    void anUnknownUserCostsThePasswordCheckAWrongPasswordCosts() {
        UserDetailsService userDetailsService = mock(UserDetailsService.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        when(passwordEncoder.encode(any())).thenReturn("decoy");
        when(userDetailsService.loadUserByUsername("ghost"))
                .thenThrow(new UsernameNotFoundException("User not found: ghost"));
        RestAuthenticationProvider provider = new RestAuthenticationProvider(
                userDetailsService, passwordEncoder, null);

        assertThatThrownBy(() -> provider.authenticate(
                RestAuthenticationToken.unauthenticated("ghost", "secret")))
                .isInstanceOf(BadCredentialsException.class);

        verify(passwordEncoder, times(1)).matches("secret", "decoy");
    }

    @Test
    void aRefusedAccountCostsThePasswordCheckAWrongPasswordCosts() {
        UserDetailsService userDetailsService = mock(UserDetailsService.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        when(passwordEncoder.encode(any())).thenReturn("decoy");
        when(userDetailsService.loadUserByUsername("locked")).thenReturn(account("locked", true, true));
        when(userDetailsService.loadUserByUsername("disabled")).thenReturn(account("disabled", false, false));
        RestAuthenticationProvider provider = new RestAuthenticationProvider(
                userDetailsService, passwordEncoder, null);

        assertThatThrownBy(() -> provider.authenticate(
                RestAuthenticationToken.unauthenticated("locked", "secret")))
                .isInstanceOf(LockedException.class);
        assertThatThrownBy(() -> provider.authenticate(
                RestAuthenticationToken.unauthenticated("disabled", "secret")))
                .isInstanceOf(DisabledException.class);

        verify(passwordEncoder, times(2)).matches("secret", "decoy");
        verify(passwordEncoder, never()).matches("secret", "encoded");
    }

    @Test
    void theRightPasswordOfAnActiveAccountSignsIn() {
        UserDetailsService userDetailsService = mock(UserDetailsService.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(account("alice", true, false));
        when(passwordEncoder.matches("secret", "encoded")).thenReturn(true);
        RestAuthenticationProvider provider = new RestAuthenticationProvider(
                userDetailsService, passwordEncoder, null);

        assertThat(provider.authenticate(RestAuthenticationToken.unauthenticated("alice", "secret"))
                .isAuthenticated()).isTrue();
    }

    private static UnifiedCustomUserDetails account(String username, boolean enabled, boolean locked) {
        return new UnifiedCustomUserDetails(UserDto.builder()
                .username(username)
                .password("encoded")
                .enabled(enabled)
                .accountLocked(locked)
                .build(), Set.of());
    }
}
