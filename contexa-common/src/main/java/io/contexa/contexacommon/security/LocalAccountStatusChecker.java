/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.contexa.contexacommon.security;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * Applies the account-state contract shared by every local authentication
 * provider. Bridge-managed external identities are evidence subjects, not
 * local-login accounts, and are therefore rejected at this boundary.
 */
public final class LocalAccountStatusChecker {

    private LocalAccountStatusChecker() {
    }

    public static void checkBeforeCredentials(UserDetails userDetails) {
        Assert.notNull(userDetails, "UserDetails cannot be null");
        if (userDetails instanceof UnifiedCustomUserDetails customUserDetails
                && customUserDetails.getAccount().isExternalAuthOnly()) {
            throw new BadCredentialsException("External authentication only account");
        }
        if (!userDetails.isEnabled()) {
            throw new DisabledException("Account is disabled");
        }
        if (!userDetails.isAccountNonLocked()) {
            throw new LockedException("Account is locked");
        }
        if (!userDetails.isAccountNonExpired()) {
            throw new AccountExpiredException("Account has expired");
        }
    }

    public static void checkAfterCredentials(UserDetails userDetails, boolean policyCredentialsExpired) {
        Assert.notNull(userDetails, "UserDetails cannot be null");
        if (!userDetails.isCredentialsNonExpired() || policyCredentialsExpired) {
            throw new CredentialsExpiredException("Password has expired");
        }
        if (userDetails instanceof UnifiedCustomUserDetails customUserDetails
                && customUserDetails.getAccount().isExternalAuthOnly()) {
            throw new BadCredentialsException("External authentication only account");
        }
    }
}
