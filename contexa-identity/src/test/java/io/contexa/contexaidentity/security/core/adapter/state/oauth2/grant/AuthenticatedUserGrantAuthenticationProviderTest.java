package io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthenticatedUserGrantAuthenticationProviderTest {

    @Mock
    private OAuth2AuthorizationService authorizationService;

    @Mock
    private OAuth2TokenGenerator<?> tokenGenerator;

    @Mock
    private UserRepository userRepository;

    @Mock
    private TransactionTemplate transactionTemplate;

    private AuthenticatedUserGrantAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        provider = new AuthenticatedUserGrantAuthenticationProvider(
                authorizationService, tokenGenerator, userRepository, transactionTemplate);

        // Make transactionTemplate execute the callback immediately
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            Consumer<Object> action = (Consumer<Object>) invocation.getArgument(0);
            action.accept(null);
            return null;
        }).when(transactionTemplate).executeWithoutResult(any());

        // Set up AuthorizationServerContext so DefaultOAuth2TokenContext.builder().build() won't throw
        AuthorizationServerContext serverContext = mock(AuthorizationServerContext.class);
        when(serverContext.getIssuer()).thenReturn("https://test-issuer.example.com");
        AuthorizationServerContextHolder.setContext(serverContext);
    }

    @AfterEach
    void tearDown() {
        AuthorizationServerContextHolder.resetContext();
    }

    @Nested
    @DisplayName("Constructor validation tests")
    class ConstructorTests {

        @Test
        @DisplayName("Constructor with null authorizationService should throw")
        void nullAuthorizationServiceThrows() {
            assertThatThrownBy(() -> new AuthenticatedUserGrantAuthenticationProvider(
                    null, tokenGenerator, userRepository, transactionTemplate))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("authorizationService cannot be null");
        }

        @Test
        @DisplayName("Constructor with null tokenGenerator should throw")
        void nullTokenGeneratorThrows() {
            assertThatThrownBy(() -> new AuthenticatedUserGrantAuthenticationProvider(
                    authorizationService, null, userRepository, transactionTemplate))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("tokenGenerator cannot be null");
        }

        @Test
        @DisplayName("Constructor with null userRepository should throw")
        void nullUserRepositoryThrows() {
            assertThatThrownBy(() -> new AuthenticatedUserGrantAuthenticationProvider(
                    authorizationService, tokenGenerator, null, transactionTemplate))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("userRepository cannot be null");
        }

        @Test
        @DisplayName("Constructor with null transactionTemplate should throw")
        void nullTransactionTemplateThrows() {
            assertThatThrownBy(() -> new AuthenticatedUserGrantAuthenticationProvider(
                    authorizationService, tokenGenerator, userRepository, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("transactionTemplate cannot be null");
        }
    }

    @Nested
    @DisplayName("supports() method tests")
    class SupportsTests {

        @Test
        @DisplayName("supports should return true for AuthenticatedUserGrantAuthenticationToken")
        void supportsAuthenticatedUserGrantToken() {
            assertThat(provider.supports(AuthenticatedUserGrantAuthenticationToken.class)).isTrue();
        }

        @Test
        @DisplayName("supports should return false for unrelated Authentication class")
        void doesNotSupportOtherAuthenticationTypes() {
            assertThat(provider.supports(Authentication.class)).isFalse();
        }
    }

    @Nested
    @DisplayName("Client validation tests")
    class ClientValidationTests {

        @Test
        @DisplayName("Unauthenticated client principal should throw INVALID_CLIENT")
        void unauthenticatedClientThrows() {
            OAuth2ClientAuthenticationToken unauthenticated = mock(OAuth2ClientAuthenticationToken.class);
            when(unauthenticated.isAuthenticated()).thenReturn(false);

            AuthenticatedUserGrantAuthenticationToken token = new AuthenticatedUserGrantAuthenticationToken(
                    unauthenticated, "testuser", null, Collections.emptyMap());

            assertThatThrownBy(() -> provider.authenticate(token))
                    .isInstanceOf(OAuth2AuthenticationException.class)
                    .satisfies(ex -> {
                        OAuth2AuthenticationException oauthEx = (OAuth2AuthenticationException) ex;
                        assertThat(oauthEx.getError().getErrorCode()).isEqualTo("invalid_client");
                    });
        }

        @Test
        @DisplayName("Null registered client should throw INVALID_CLIENT")
        void nullRegisteredClientThrows() {
            OAuth2ClientAuthenticationToken clientPrincipal = createAuthenticatedClient(null);

            AuthenticatedUserGrantAuthenticationToken token = new AuthenticatedUserGrantAuthenticationToken(
                    clientPrincipal, "testuser", null, Collections.emptyMap());

            assertThatThrownBy(() -> provider.authenticate(token))
                    .isInstanceOf(OAuth2AuthenticationException.class)
                    .satisfies(ex -> {
                        OAuth2AuthenticationException oauthEx = (OAuth2AuthenticationException) ex;
                        assertThat(oauthEx.getError().getErrorCode()).isEqualTo("invalid_client");
                    });
        }

        @Test
        @DisplayName("Client without AUTHENTICATED_USER grant type should throw UNAUTHORIZED_CLIENT")
        void clientWithoutGrantTypeThrows() {
            RegisteredClient registeredClient = mock(RegisteredClient.class);
            when(registeredClient.getAuthorizationGrantTypes()).thenReturn(
                    Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));

            OAuth2ClientAuthenticationToken clientPrincipal = createAuthenticatedClient(registeredClient);

            AuthenticatedUserGrantAuthenticationToken token = new AuthenticatedUserGrantAuthenticationToken(
                    clientPrincipal, "testuser", null, Collections.emptyMap());

            assertThatThrownBy(() -> provider.authenticate(token))
                    .isInstanceOf(OAuth2AuthenticationException.class)
                    .satisfies(ex -> {
                        OAuth2AuthenticationException oauthEx = (OAuth2AuthenticationException) ex;
                        assertThat(oauthEx.getError().getErrorCode()).isEqualTo("unauthorized_client");
                    });
        }
    }

    @Nested
    @DisplayName("User not found tests")
    class UserNotFoundTests {

        @Test
        @DisplayName("User not found in database should throw INVALID_GRANT")
        void userNotFoundThrows() {
            RegisteredClient registeredClient = createValidRegisteredClient();
            OAuth2ClientAuthenticationToken clientPrincipal = createAuthenticatedClient(registeredClient);

            when(userRepository.findByUsernameWithGroupsRolesAndPermissions("nonexistent"))
                    .thenReturn(Optional.empty());

            AuthenticatedUserGrantAuthenticationToken token = new AuthenticatedUserGrantAuthenticationToken(
                    clientPrincipal, "nonexistent", null, Collections.emptyMap());

            assertThatThrownBy(() -> provider.authenticate(token))
                    .isInstanceOf(OAuth2AuthenticationException.class)
                    .satisfies(ex -> {
                        OAuth2AuthenticationException oauthEx = (OAuth2AuthenticationException) ex;
                        assertThat(oauthEx.getError().getErrorCode()).isEqualTo("invalid_grant");
                        assertThat(oauthEx.getError().getDescription()).contains("User not found");
                    });
        }
    }

    @Nested
    @DisplayName("Scope intersection tests")
    class ScopeTests {

        @Test
        @DisplayName("Requested scopes should be intersected with allowed scopes")
        void requestedScopesIntersectedWithAllowed() {
            RegisteredClient registeredClient = createValidRegisteredClient();
            when(registeredClient.getScopes()).thenReturn(Set.of("read", "write", "admin"));

            OAuth2ClientAuthenticationToken clientPrincipal = createAuthenticatedClient(registeredClient);
            // Disable refresh token for simplicity
            when(clientPrincipal.getClientAuthenticationMethod())
                    .thenReturn(ClientAuthenticationMethod.NONE);

            Users user = createMockUser("testuser");
            when(userRepository.findByUsernameWithGroupsRolesAndPermissions("testuser"))
                    .thenReturn(Optional.of(user));

            OAuth2AccessToken generatedAccessToken = createMockAccessToken(Set.of("read"));
            when(tokenGenerator.generate(any(OAuth2TokenContext.class))).thenReturn(generatedAccessToken);

            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("scope", "read delete");

            AuthenticatedUserGrantAuthenticationToken token = new AuthenticatedUserGrantAuthenticationToken(
                    clientPrincipal, "testuser", null, additionalParams);

            Authentication result = provider.authenticate(token);

            assertThat(result).isInstanceOf(OAuth2AccessTokenAuthenticationToken.class);
            OAuth2AccessTokenAuthenticationToken accessTokenResult =
                    (OAuth2AccessTokenAuthenticationToken) result;
            // "delete" is not in allowed scopes, only "read" should remain
            assertThat(accessTokenResult.getAccessToken().getScopes()).contains("read");
            assertThat(accessTokenResult.getAccessToken().getScopes()).doesNotContain("delete");
        }

        @Test
        @DisplayName("No requested scope should use all allowed scopes")
        void noRequestedScopeUsesAllAllowed() {
            RegisteredClient registeredClient = createValidRegisteredClient();
            when(registeredClient.getScopes()).thenReturn(Set.of("read", "write"));

            OAuth2ClientAuthenticationToken clientPrincipal = createAuthenticatedClient(registeredClient);
            when(clientPrincipal.getClientAuthenticationMethod())
                    .thenReturn(ClientAuthenticationMethod.NONE);

            Users user = createMockUser("testuser");
            when(userRepository.findByUsernameWithGroupsRolesAndPermissions("testuser"))
                    .thenReturn(Optional.of(user));

            OAuth2AccessToken generatedAccessToken = createMockAccessToken(Set.of("read", "write"));
            when(tokenGenerator.generate(any(OAuth2TokenContext.class))).thenReturn(generatedAccessToken);

            AuthenticatedUserGrantAuthenticationToken token = new AuthenticatedUserGrantAuthenticationToken(
                    clientPrincipal, "testuser", null, Collections.emptyMap());

            Authentication result = provider.authenticate(token);

            assertThat(result).isInstanceOf(OAuth2AccessTokenAuthenticationToken.class);
            OAuth2AccessTokenAuthenticationToken accessTokenResult =
                    (OAuth2AccessTokenAuthenticationToken) result;
            assertThat(accessTokenResult.getAccessToken().getScopes())
                    .containsExactlyInAnyOrder("read", "write");
        }
    }

    @Nested
    @DisplayName("Refresh token conditional generation tests")
    class RefreshTokenTests {

        @Test
        @DisplayName("Client with REFRESH_TOKEN grant and non-NONE auth method should generate refresh token")
        void generatesRefreshTokenWhenConditionsMet() {
            RegisteredClient registeredClient = createValidRegisteredClient();
            when(registeredClient.getAuthorizationGrantTypes()).thenReturn(
                    Set.of(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER,
                            AuthorizationGrantType.REFRESH_TOKEN));
            when(registeredClient.getScopes()).thenReturn(Set.of("read"));

            OAuth2ClientAuthenticationToken clientPrincipal = createAuthenticatedClient(registeredClient);
            when(clientPrincipal.getClientAuthenticationMethod())
                    .thenReturn(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

            Users user = createMockUser("testuser");
            when(userRepository.findByUsernameWithGroupsRolesAndPermissions("testuser"))
                    .thenReturn(Optional.of(user));

            OAuth2AccessToken generatedAccessToken = createMockAccessToken(Set.of("read"));
            OAuth2RefreshToken refreshTokenGenerated = new OAuth2RefreshToken(
                    "refresh-token-value", Instant.now(), Instant.now().plusSeconds(3600));

            when(tokenGenerator.generate(any(OAuth2TokenContext.class)))
                    .thenReturn(generatedAccessToken)
                    .thenReturn(refreshTokenGenerated);

            AuthenticatedUserGrantAuthenticationToken token = new AuthenticatedUserGrantAuthenticationToken(
                    clientPrincipal, "testuser", null, Collections.emptyMap());

            Authentication result = provider.authenticate(token);

            assertThat(result).isInstanceOf(OAuth2AccessTokenAuthenticationToken.class);
            OAuth2AccessTokenAuthenticationToken accessTokenResult =
                    (OAuth2AccessTokenAuthenticationToken) result;
            assertThat(accessTokenResult.getRefreshToken()).isNotNull();
            assertThat(accessTokenResult.getRefreshToken().getTokenValue())
                    .isEqualTo("refresh-token-value");
        }

        @Test
        @DisplayName("Client with NONE auth method should not generate refresh token")
        void noRefreshTokenForNoneAuthMethod() {
            RegisteredClient registeredClient = createValidRegisteredClient();
            when(registeredClient.getAuthorizationGrantTypes()).thenReturn(
                    Set.of(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER,
                            AuthorizationGrantType.REFRESH_TOKEN));
            when(registeredClient.getScopes()).thenReturn(Set.of("read"));

            OAuth2ClientAuthenticationToken clientPrincipal = createAuthenticatedClient(registeredClient);
            when(clientPrincipal.getClientAuthenticationMethod())
                    .thenReturn(ClientAuthenticationMethod.NONE);

            Users user = createMockUser("testuser");
            when(userRepository.findByUsernameWithGroupsRolesAndPermissions("testuser"))
                    .thenReturn(Optional.of(user));

            OAuth2AccessToken generatedAccessToken = createMockAccessToken(Set.of("read"));
            when(tokenGenerator.generate(any(OAuth2TokenContext.class)))
                    .thenReturn(generatedAccessToken);

            AuthenticatedUserGrantAuthenticationToken token = new AuthenticatedUserGrantAuthenticationToken(
                    clientPrincipal, "testuser", null, Collections.emptyMap());

            Authentication result = provider.authenticate(token);

            assertThat(result).isInstanceOf(OAuth2AccessTokenAuthenticationToken.class);
            OAuth2AccessTokenAuthenticationToken accessTokenResult =
                    (OAuth2AccessTokenAuthenticationToken) result;
            assertThat(accessTokenResult.getRefreshToken()).isNull();
        }

        @Test
        @DisplayName("Client without REFRESH_TOKEN grant type should not generate refresh token")
        void noRefreshTokenWithoutGrantType() {
            RegisteredClient registeredClient = createValidRegisteredClient();
            // Only AUTHENTICATED_USER, no REFRESH_TOKEN
            when(registeredClient.getAuthorizationGrantTypes()).thenReturn(
                    Set.of(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER));
            when(registeredClient.getScopes()).thenReturn(Set.of("read"));

            OAuth2ClientAuthenticationToken clientPrincipal = createAuthenticatedClient(registeredClient);
            when(clientPrincipal.getClientAuthenticationMethod())
                    .thenReturn(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

            Users user = createMockUser("testuser");
            when(userRepository.findByUsernameWithGroupsRolesAndPermissions("testuser"))
                    .thenReturn(Optional.of(user));

            OAuth2AccessToken generatedAccessToken = createMockAccessToken(Set.of("read"));
            when(tokenGenerator.generate(any(OAuth2TokenContext.class)))
                    .thenReturn(generatedAccessToken);

            AuthenticatedUserGrantAuthenticationToken token = new AuthenticatedUserGrantAuthenticationToken(
                    clientPrincipal, "testuser", null, Collections.emptyMap());

            Authentication result = provider.authenticate(token);

            assertThat(result).isInstanceOf(OAuth2AccessTokenAuthenticationToken.class);
            OAuth2AccessTokenAuthenticationToken accessTokenResult =
                    (OAuth2AccessTokenAuthenticationToken) result;
            assertThat(accessTokenResult.getRefreshToken()).isNull();
        }
    }

    @Nested
    @DisplayName("Token generation failure tests")
    class TokenGenerationTests {

        @Test
        @DisplayName("Null access token from generator should throw SERVER_ERROR")
        void nullAccessTokenThrows() {
            RegisteredClient registeredClient = createValidRegisteredClient();
            when(registeredClient.getScopes()).thenReturn(Set.of("read"));

            OAuth2ClientAuthenticationToken clientPrincipal = createAuthenticatedClient(registeredClient);

            Users user = createMockUser("testuser");
            when(userRepository.findByUsernameWithGroupsRolesAndPermissions("testuser"))
                    .thenReturn(Optional.of(user));

            when(tokenGenerator.generate(any(OAuth2TokenContext.class))).thenReturn(null);

            AuthenticatedUserGrantAuthenticationToken token = new AuthenticatedUserGrantAuthenticationToken(
                    clientPrincipal, "testuser", null, Collections.emptyMap());

            assertThatThrownBy(() -> provider.authenticate(token))
                    .isInstanceOf(OAuth2AuthenticationException.class)
                    .satisfies(ex -> {
                        OAuth2AuthenticationException oauthEx = (OAuth2AuthenticationException) ex;
                        assertThat(oauthEx.getError().getErrorCode()).isEqualTo("server_error");
                        assertThat(oauthEx.getError().getDescription())
                                .contains("failed to generate the access token");
                    });
        }
    }

    // -- helper methods --

    private OAuth2ClientAuthenticationToken createAuthenticatedClient(RegisteredClient registeredClient) {
        OAuth2ClientAuthenticationToken clientPrincipal = mock(OAuth2ClientAuthenticationToken.class);
        when(clientPrincipal.isAuthenticated()).thenReturn(true);
        when(clientPrincipal.getRegisteredClient()).thenReturn(registeredClient);
        when(clientPrincipal.getClientAuthenticationMethod())
                .thenReturn(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        return clientPrincipal;
    }

    private RegisteredClient createValidRegisteredClient() {
        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClient.getAuthorizationGrantTypes()).thenReturn(
                Set.of(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER));
        when(registeredClient.getScopes()).thenReturn(Set.of("read", "write"));
        when(registeredClient.getId()).thenReturn("test-client-id");
        return registeredClient;
    }

    private Users createMockUser(String username) {
        Users user = mock(Users.class);
        when(user.getUsername()).thenReturn(username);
        when(user.getRoleNames()).thenReturn(List.of("ROLE_USER"));
        return user;
    }

    private OAuth2AccessToken createMockAccessToken(Set<String> scopes) {
        Instant now = Instant.now();
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "test-access-token-value",
                now,
                now.plusSeconds(3600),
                scopes);
    }
}
