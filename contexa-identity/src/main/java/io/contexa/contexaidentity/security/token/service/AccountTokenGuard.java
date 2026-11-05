/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.token.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * What a person's token answers to: the account as it is now. A token and the principal stored with it say what the user
 * could do at the sign-in, so neither speaks for the user afterwards. A renewal reads the account, stops where a sign-in
 * would stop, and hands out what the account holds; the same rules serve the refresh entry point and the token endpoint.
 *
 * <p>When the account cannot be read the failure stays a failure and nothing is issued: unlike a session, which goes on
 * as it was, a renewal has nothing to go on with.</p>
 */
public final class AccountTokenGuard {

    /** The claim in which an access token names what its user could do when it was issued. */
    public static final String ROLES_CLAIM = "roles";

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String SCOPE_PREFIX = "SCOPE_";

    private final Supplier<UserDetailsService> accounts;
    private final Supplier<ZeroTrustActionRepository> actions;

    /**
     * @param accounts the store the sign-in and the resource server read, resolved at its first use
     * @param actions  the decisions in force, or null from it where no decision answers a renewal
     */
    public AccountTokenGuard(Supplier<UserDetailsService> accounts, Supplier<ZeroTrustActionRepository> actions) {
        Assert.notNull(accounts, "accounts cannot be null");
        Assert.notNull(actions, "actions cannot be null");
        this.accounts = accounts;
        this.actions = actions;
    }

    /**
     * Admits a renewal, or refuses it for a decision in force or for the account.
     *
     * @return the account as it is now
     */
    public UserDetails admitRenewal(String username) {
        refuseWhileRestricted(actions.get(), username);
        return activeAccount(username);
    }

    /**
     * The account as it is now, or a refusal when it is gone, disabled or locked. {@code invalid_grant} is the answer of
     * RFC 6749 to a grant that no longer stands, and it leaves the refresh token unspent: a lock that ends lets it renew.
     */
    public UserDetails activeAccount(String username) {
        UserDetails account;
        try {
            account = accounts.get().loadUserByUsername(username);
        } catch (UsernameNotFoundException gone) {
            throw refused();
        }
        if (disabled(account) || !account.isAccountNonLocked()) {
            throw refused();
        }
        return account;
    }

    private static OAuth2AuthenticationException refused() {
        return new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
                "The account does not allow this token to be renewed", null));
    }

    /** Refuses a renewal while the decision in force stops the user; without a store of decisions nothing does. */
    static void refuseWhileRestricted(@Nullable ZeroTrustActionRepository repository, String username) {
        if (repository == null) {
            return;
        }
        ZeroTrustAction action = repository.getCurrentAction(ZeroTrustUserKey.person(username));
        if (action == ZeroTrustAction.BLOCK || action == ZeroTrustAction.ESCALATE) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED,
                    "Token refresh is not allowed while the zero trust action is " + action, null));
        }
        if (action == ZeroTrustAction.CHALLENGE) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2TokenService.MFA_CHALLENGE_REQUIRED_ERROR,
                    "Token refresh requires completing the zero trust MFA challenge", null));
        }
    }

    /**
     * Whether an administrator has disabled the account. {@link UserDetails#isEnabled()} of Contexa's own account is also
     * false for one that signs in elsewhere only, which keeps it from a password here and does not disable it.
     */
    public static boolean disabled(UserDetails account) {
        return account instanceof UnifiedCustomUserDetails details ? !details.getAccount().isEnabled() : !account.isEnabled();
    }

    /**
     * What the {@value #ROLES_CLAIM} claim of a renewed token says: the account's roles and the token's scopes, as a sign-in
     * writes them. Permissions stay out, as at the sign-in: an account can hold many, and the token often travels in a cookie.
     */
    public static List<String> rolesClaim(UserDetails account, Collection<String> scopes) {
        Stream<String> roles = account.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith(ROLE_PREFIX))
                .map(AccountTokenGuard::withoutRolePrefix)
                .sorted();
        Stream<String> scopeNames = scopes.stream().map(scope -> SCOPE_PREFIX + scope).sorted();
        return Stream.concat(roles, scopeNames).distinct().collect(Collectors.toList());
    }

    /** Whether a {@value #ROLES_CLAIM} claim names a right the account does not hold; scopes are the token's own. */
    public static boolean namesRightsBeyond(@Nullable Object rolesClaim, UserDetails account) {
        if (!(rolesClaim instanceof Collection<?> named)) {
            return false;
        }
        Set<String> held = account.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(AccountTokenGuard::withoutRolePrefix)
                .collect(Collectors.toSet());
        return named.stream()
                .map(String::valueOf)
                .filter(name -> !name.startsWith(SCOPE_PREFIX))
                .map(AccountTokenGuard::withoutRolePrefix)
                .anyMatch(name -> !held.contains(name));
    }

    private static String withoutRolePrefix(String authority) {
        return authority.startsWith(ROLE_PREFIX) ? authority.substring(ROLE_PREFIX.length()) : authority;
    }
}
