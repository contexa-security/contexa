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
package io.contexa.contexaiam.security.xacml.pip.context;

import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Where Contexa owns the sign-in the bridge keeps no copy of Contexa's own accounts, so the decisions find the account the
 * way they did through the copy's result: the same user, with the same roles and groups, for a session and for a token.
 */
class DefaultContextHandlerContexaAccountTest {

    private final UserRepository users = mock(UserRepository.class);
    private final ContexaCacheService cache = mock(ContexaCacheService.class);
    private final Users admin = account(1L, "admin", false);

    @BeforeEach
    void setUp() {
        when(cache.get(anyString(), any(), any(), anyString()))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
        when(users.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(admin));
        when(users.findByUsernameWithGroupsRolesAndPermissions("admin")).thenReturn(Optional.of(admin));
    }

    @Test
    void aSessionOfTheAccountGivesTheSameSubjectWithAndWithoutTheCopysResult() {
        UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(UserDto.builder().id(1L).username("admin")
                .password("x").enabled(true).build(), Set.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        Authentication session = UsernamePasswordAuthenticationToken.authenticated(details, null, details.getAuthorities());

        AuthorizationContext before = handler(SecurityOwnershipMode.CONTEXA_OWNED, true).create(session, withCopyOf(1L));
        AuthorizationContext after = handler(SecurityOwnershipMode.CONTEXA_OWNED, true).create(session, request());

        assertTheSameSubject(before, after);
    }

    @Test
    void aTokenOfTheAccountGivesTheSameSubjectWithAndWithoutTheCopysResult() {
        Authentication token = new JwtAuthenticationToken(jwt("admin", "default-client"),
                AuthorityUtils.createAuthorityList("ROLE_ADMIN", "SCOPE_read"));

        AuthorizationContext before = handler(SecurityOwnershipMode.CONTEXA_OWNED, true).create(token, withCopyOf(1L));
        AuthorizationContext after = handler(SecurityOwnershipMode.CONTEXA_OWNED, true).create(token, request());

        assertTheSameSubject(before, after);
    }

    /** Contexa's decision state re-wraps the authentication and keeps the token as its principal. */
    @Test
    void aTokenRewrappedByTheDecisionStateIsStillTheAccount() {
        Authentication rewrapped = UsernamePasswordAuthenticationToken.authenticated(jwt("admin", "default-client"), null,
                AuthorityUtils.createAuthorityList("ROLE_ADMIN"));

        AuthorizationContext after = handler(SecurityOwnershipMode.CONTEXA_OWNED, true).create(rewrapped, request());

        assertThat(after.subjectEntity()).isSameAs(admin);
    }

    @Test
    void aClientsOwnTokenIsNoAccountAndKeepsItsCopy() {
        Authentication client = new JwtAuthenticationToken(jwt("admin", "admin"), AuthorityUtils.createAuthorityList("SCOPE_read"));
        Users copy = account(9L, "brg_admin_client", true);
        when(users.findByIdWithGroupsRolesAndPermissions(9L)).thenReturn(Optional.of(copy));

        assertThat(handler(SecurityOwnershipMode.CONTEXA_OWNED, true).create(client, request()).subjectEntity())
                .as("an account of the client's name is a person's").isNull();
        assertThat(handler(SecurityOwnershipMode.CONTEXA_OWNED, true).create(client, withCopyOf(9L)).subjectEntity())
                .isSameAs(copy);
        verify(users, never()).findByUsernameWithGroupsRolesAndPermissions(anyString());
    }

    @Test
    void whereTheApplicationOwnsTheSignInATokenNamesNoAccountOfContexa() {
        Authentication token = new JwtAuthenticationToken(jwt("admin", "default-client"), AuthorityUtils.createAuthorityList());

        assertThat(handler(SecurityOwnershipMode.HOST_OWNED, true).create(token, request()).subjectEntity()).isNull();
        verify(users, never()).findByUsernameWithGroupsRolesAndPermissions(anyString());
    }

    @Test
    void whileTheApplicationsStoreSignsTheUsersInATokenNamesNoAccountOfContexa() {
        Authentication token = new JwtAuthenticationToken(jwt("admin", "default-client"), AuthorityUtils.createAuthorityList());

        assertThat(handler(SecurityOwnershipMode.CONTEXA_OWNED, false).create(token, request()).subjectEntity()).isNull();
        verify(users, never()).findByUsernameWithGroupsRolesAndPermissions(anyString());
    }

    @Test
    void aCopyOfTheSameNameIsNoAccount() {
        Users copy = account(5L, "brg_x", true);
        when(users.findByUsernameWithGroupsRolesAndPermissions("brg_x")).thenReturn(Optional.of(copy));
        Authentication token = new JwtAuthenticationToken(jwt("brg_x", "default-client"), AuthorityUtils.createAuthorityList());

        assertThat(handler(SecurityOwnershipMode.CONTEXA_OWNED, true).create(token, request()).subjectEntity()).isNull();
    }

    private DefaultContextHandler handler(SecurityOwnershipMode ownership, boolean contexaAccountsSignIn) {
        BridgeProperties properties = new BridgeProperties();
        properties.setOwnership(ownership);
        return new DefaultContextHandler(users, cache, properties, () -> contexaAccountsSignIn);
    }

    private static void assertTheSameSubject(AuthorizationContext before, AuthorizationContext after) {
        assertThat(after.subjectEntity()).isSameAs(before.subjectEntity());
        assertThat(after.attributes()).isEqualTo(before.attributes());
        assertThat(after.attributes().get("userRoles")).asList().containsExactly("ROLE_ADMIN");
        assertThat(after.attributes().get("userGroups")).asList().containsExactly("administrators");
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setRemoteAddr("203.0.113.5");
        return request;
    }

    private static MockHttpServletRequest withCopyOf(Long userId) {
        MockHttpServletRequest request = request();
        request.setAttribute(BridgeRequestAttributes.USER_SYNC_RESULT,
                new BridgeUserMirrorSyncResult(userId, "admin", "admin", null, false, false, false, false));
        return request;
    }

    private static Jwt jwt(String subject, String clientId) {
        return Jwt.withTokenValue("token").header("alg", "none").subject(subject).claim("client_id", clientId)
                .issuedAt(Instant.parse("2026-11-11T00:00:00Z")).expiresAt(Instant.parse("2026-11-11T01:00:00Z")).build();
    }

    private static Users account(Long id, String username, boolean copy) {
        Users user = mock(Users.class);
        when(user.getId()).thenReturn(id);
        when(user.getUsername()).thenReturn(username);
        when(user.isBridgeManaged()).thenReturn(copy);
        Group group = mock(Group.class);
        when(group.getName()).thenReturn("administrators");
        UserGroup membership = mock(UserGroup.class);
        when(membership.getGroup()).thenReturn(group);
        when(user.getUserGroups()).thenReturn(Set.of(membership));
        when(user.getRoleNames()).thenReturn(List.of("ROLE_ADMIN"));
        return user;
    }
}
