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

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AccountTokenGuardTest {

    private final UserDetailsService accounts = mock(UserDetailsService.class);
    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final AccountTokenGuard guard = new AccountTokenGuard(() -> accounts, () -> actions);

    private static UserDto.UserDtoBuilder alice() {
        return UserDto.builder().id(1L).username("alice").password("{noop}x").enabled(true);
    }

    private static UnifiedCustomUserDetails details(UserDto account, String... authorities) {
        Set<GrantedAuthority> granted = Arrays.stream(authorities).map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        return new UnifiedCustomUserDetails(account, granted);
    }

    private void assertRefused(String error) {
        assertThatThrownBy(() -> guard.admitRenewal("alice"))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class,
                        refused -> assertThat(refused.getError().getErrorCode()).isEqualTo(error));
    }

    @Test
    @DisplayName("An account in good standing is admitted and read as it is now")
    void anAccountInGoodStanding() {
        UnifiedCustomUserDetails account = details(alice().build(), "ROLE_USER");
        when(accounts.loadUserByUsername("alice")).thenReturn(account);

        assertThat(guard.admitRenewal("alice")).isSameAs(account);
    }

    @Test
    @DisplayName("An account that is gone renews nothing")
    void anAccountGone() {
        when(accounts.loadUserByUsername("alice")).thenThrow(new UsernameNotFoundException("gone"));

        assertRefused(OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Test
    @DisplayName("A disabled account renews nothing")
    void aDisabledAccount() {
        when(accounts.loadUserByUsername("alice")).thenReturn(details(alice().enabled(false).build(), "ROLE_USER"));

        assertRefused(OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Test
    @DisplayName("A locked account renews nothing while the lock lasts")
    void aLockedAccount() {
        when(accounts.loadUserByUsername("alice")).thenReturn(details(alice().accountLocked(true)
                .lockExpiresAt(LocalDateTime.now().plusMinutes(5)).build(), "ROLE_USER"));

        assertRefused(OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Test
    @DisplayName("A lock past its end stands in nobody's way, as at the sign-in")
    void aLockPastItsEnd() {
        UnifiedCustomUserDetails account = details(alice().accountLocked(true)
                .lockExpiresAt(LocalDateTime.now().minusMinutes(5)).build(), "ROLE_USER");
        when(accounts.loadUserByUsername("alice")).thenReturn(account);

        assertThat(guard.admitRenewal("alice")).isSameAs(account);
    }

    @Test
    @DisplayName("An account that signs in elsewhere only is no disabled account")
    void anExternalAccount() {
        UnifiedCustomUserDetails account = details(alice().externalAuthOnly(true).build(), "ROLE_USER");
        when(accounts.loadUserByUsername("alice")).thenReturn(account);

        assertThat(guard.admitRenewal("alice")).isSameAs(account);
    }

    @Test
    @DisplayName("A store of the application answers by the UserDetails contract")
    void anApplicationsUser() {
        when(accounts.loadUserByUsername("alice"))
                .thenReturn(User.withUsername("alice").password("{noop}x").accountLocked(true).build());
        assertRefused(OAuth2ErrorCodes.INVALID_GRANT);

        when(accounts.loadUserByUsername("alice"))
                .thenReturn(User.withUsername("alice").password("{noop}x").disabled(true).build());
        assertRefused(OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Test
    @DisplayName("A store that fails is no answer: the failure stays a failure, and nothing is issued")
    void aStoreThatFails() {
        when(accounts.loadUserByUsername("alice")).thenThrow(new DataAccessResourceFailureException("database down"));

        assertThatThrownBy(() -> guard.admitRenewal("alice")).isInstanceOf(DataAccessResourceFailureException.class);
    }

    @ParameterizedTest
    @EnumSource(value = ZeroTrustAction.class, names = {"BLOCK", "ESCALATE"})
    @DisplayName("A stored BLOCK or ESCALATE refuses the renewal")
    void aStoredRestriction(ZeroTrustAction action) {
        when(accounts.loadUserByUsername("alice")).thenReturn(details(alice().build(), "ROLE_USER"));
        when(actions.getCurrentAction("alice")).thenReturn(action);

        assertRefused(OAuth2ErrorCodes.ACCESS_DENIED);
    }

    @Test
    @DisplayName("A stored CHALLENGE asks for the code first")
    void aStoredChallenge() {
        when(accounts.loadUserByUsername("alice")).thenReturn(details(alice().build(), "ROLE_USER"));
        when(actions.getCurrentAction("alice")).thenReturn(ZeroTrustAction.CHALLENGE);

        assertRefused(OAuth2TokenService.MFA_CHALLENGE_REQUIRED_ERROR);
    }

    @Test
    @DisplayName("Without a decision store only the account answers")
    void withoutADecisionStore() {
        UnifiedCustomUserDetails account = details(alice().build(), "ROLE_USER");
        when(accounts.loadUserByUsername("alice")).thenReturn(account);

        assertThat(new AccountTokenGuard(() -> accounts, () -> null).admitRenewal("alice")).isSameAs(account);
    }

    @Test
    @DisplayName("The roles claim holds the account's roles and the token's scopes, as a new sign-in writes them")
    void theRolesClaim() {
        UserDetails account = details(alice().build(), "ROLE_ADMIN", "ROLE_USER", "ORDER_READ", "ORDER_WRITE");

        assertThat(AccountTokenGuard.rolesClaim(account, Set.of("read")))
                .containsExactly("ADMIN", "USER", "SCOPE_read");
    }

    @Test
    @DisplayName("An account without roles leaves the token its scopes")
    void theRolesClaimOfAnAccountWithoutRoles() {
        assertThat(AccountTokenGuard.rolesClaim(details(alice().build()), Set.of("read"))).containsExactly("SCOPE_read");
    }

    @Test
    @DisplayName("A claim naming a role the account lost runs beyond it; what it holds, and the scopes, do not")
    void aClaimBeyondTheAccount() {
        UserDetails account = details(alice().build(), "ROLE_USER", "ORDER_READ");

        assertThat(AccountTokenGuard.namesRightsBeyond(List.of("ADMIN", "SCOPE_read"), account)).isTrue();
        assertThat(AccountTokenGuard.namesRightsBeyond(List.of("USER", "ORDER_READ", "SCOPE_read"), account)).isFalse();
        assertThat(AccountTokenGuard.namesRightsBeyond(List.of("ROLE_USER"), account)).isFalse();
        assertThat(AccountTokenGuard.namesRightsBeyond(List.of(), account)).isFalse();
    }

    @Test
    @DisplayName("A token that names no roles has nothing to run beyond the account")
    void aClaimThatIsNotThere() {
        assertThat(AccountTokenGuard.namesRightsBeyond(null, details(alice().build()))).isFalse();
        assertThat(AccountTokenGuard.namesRightsBeyond("ADMIN", details(alice().build()))).isFalse();
    }
}
