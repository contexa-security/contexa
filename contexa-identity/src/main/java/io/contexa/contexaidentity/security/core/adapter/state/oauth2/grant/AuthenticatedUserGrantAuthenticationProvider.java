package io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant;

import io.contexa.contexaidentity.security.filter.MfaGrantedAuthority;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

import java.security.Principal;
import java.util.*;

/**
 * Authenticated User Grant Type을 처리하는 AuthenticationProvider
 *
 * <p>MFA 인증이 완료된 사용자의 정보를 기반으로 OAuth2 Access Token을 발급합니다.
 * Spring Authorization Server의 표준 토큰 생성 메커니즘을 사용합니다.
 *
 * <h3>처리 흐름</h3>
 * <ol>
 *   <li>클라이언트 인증 확인 (Client Credentials 검증)</li>
 *   <li>Grant Type 지원 확인</li>
 *   <li>사용자 실제 존재 여부 DB 검증</li>
 *   <li>실제 DB 권한 조회 및 Authentication 생성</li>
 *   <li>OAuth2TokenContext 생성</li>
 *   <li>OAuth2TokenGenerator로 Access Token 생성</li>
 *   <li>Refresh Token 생성 (조건부)</li>
 *   <li>OAuth2Authorization 저장</li>
 *   <li>OAuth2AccessTokenAuthenticationToken 반환</li>
 * </ol>
 *
 * <h3>보안 정책</h3>
 * <ul>
 *   <li>MFA 인증 완료 전제: 사용자 인증과 계정 상태는 MFA 단계에서 이미 검증됨</li>
 *   <li>토큰 발급 시점: DB에서 최신 사용자 정보 및 권한 조회</li>
 *   <li>이중 인증 없음: SecurityContext 검증 불필요 (MFA 완료 = 인증 완료)</li>
 * </ul>
 *
 * @since 2024.12
 * @since 2025.01 - 실제 DB 조회 및 권한 적용 구현
 */
@Slf4j
public class AuthenticatedUserGrantAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final OAuth2AuthorizationService authorizationService;
    private final UserRepository userRepository;
    private final TransactionTemplate transactionTemplate;

    public AuthenticatedUserGrantAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator,
            UserRepository userRepository,
            TransactionTemplate transactionTemplate) {

        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        Assert.notNull(userRepository, "userRepository cannot be null");
        Assert.notNull(transactionTemplate, "transactionTemplate cannot be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.userRepository = userRepository;
        this.transactionTemplate = transactionTemplate;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AuthenticatedUserGrantAuthenticationToken authenticationToken =
                (AuthenticatedUserGrantAuthenticationToken) authentication;

        // 1. 클라이언트 인증 확인
        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient(authenticationToken);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (log.isTraceEnabled()) {
            log.trace("Retrieved registered client: {}", registeredClient.getId());
        }

        // 2. Grant Type 지원 확인
        assert registeredClient != null;
        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // 3. 사용자 조회 및 실제 권한으로 Authentication 생성
        String username = authenticationToken.getUsername();
        Users user = loadUserFromDatabase(username);
        Authentication userAuthentication = createAuthenticatedUser(user, registeredClient.getScopes());

        if (log.isDebugEnabled()) {
            log.debug("Created authenticated user with DB authorities for: {}", username);
        }

        // 4. OAuth2TokenContext 생성 (Access Token)
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(registeredClient.getScopes())
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrant(authenticationToken);

        // Device ID 추가 (OAuth2TokenCustomizer 에서 사용)
        if (authenticationToken.getDeviceId() != null) {
            tokenContextBuilder.put("device_id", authenticationToken.getDeviceId());
        }

        // 5. Access Token 생성 (OAuth2TokenGenerator 사용)
        OAuth2TokenContext tokenContext = tokenContextBuilder.build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        if (log.isTraceEnabled()) {
            log.trace("Generated access token");
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                tokenContext.getAuthorizedScopes());

        // 6. Refresh Token 생성
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
                !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

            tokenContext = tokenContextBuilder
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();

            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            if (log.isTraceEnabled()) {
                log.trace("Generated refresh token");
            }

            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
        }

        // 7. OAuth2Authorization 생성 및 저장
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(userAuthentication.getName())
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .authorizedScopes(registeredClient.getScopes())
                .attribute(Principal.class.getName(), userAuthentication);

        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            ((ClaimAccessor) generatedAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        if (refreshToken != null) {
            authorizationBuilder.refreshToken(refreshToken);
        }

        OAuth2Authorization authorization = authorizationBuilder.build();

        // 트랜잭션 내에서 저장 (auto-commit: false 환경 지원)
        transactionTemplate.executeWithoutResult(status -> {
            this.authorizationService.save(authorization);
            if (log.isDebugEnabled()) {
                log.debug("Saved OAuth2Authorization for user: {} in transaction", userAuthentication.getName());
            }
        });

        // 8. OAuth2AccessTokenAuthenticationToken 반환
        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient, clientPrincipal, accessToken, refreshToken, Collections.emptyMap());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AuthenticatedUserGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
            Authentication authentication) {

        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    /**
     * DB에서 사용자 조회
     *
     * <p>MFA 인증이 완료된 상태이므로 계정 상태 재검증은 하지 않습니다.
     * 사용자 존재 여부만 확인합니다.
     *
     * @param username 사용자 이름
     * @return 사용자 엔티티
     * @throws OAuth2AuthenticationException 사용자가 존재하지 않을 경우
     */
    private Users loadUserFromDatabase(String username) {
        return userRepository.findByUsernameWithGroupsRolesAndPermissions(username)
                .orElseThrow(() -> {
                    log.warn("User not found in database: {}", username);
                    return new OAuth2AuthenticationException(
                            new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
                                    "User not found: " + username, ERROR_URI));
                });
    }

    /**
     * 실제 DB 권한으로 인증된 사용자 Authentication 생성
     *
     * <p>DB에 저장된 실제 권한(roles)을 조회하고, OAuth2 스코프를 SCOPE_ 권한으로 추가합니다.
     *
     * @param user 사용자 엔티티
     * @param scopes OAuth2 스코프
     * @return 인증된 사용자 Authentication
     */
    private Authentication createAuthenticatedUser(Users user, Set<String> scopes) {

        // DB에서 역할 이름들을 가져와서 MfaGrantedAuthority 생성
        List<GrantedAuthority> allAuthorities = new ArrayList<>();
        user.getRoleNames().stream()
                .map(MfaGrantedAuthority::new)
                .forEach(allAuthorities::add);

        // OAuth2 스코프를 SCOPE_ 권한으로 추가
        if (scopes != null && !scopes.isEmpty()) {
            scopes.forEach(scope ->
                    allAuthorities.add(new MfaGrantedAuthority("SCOPE_" + scope)));
        }

        if (log.isTraceEnabled()) {
            log.trace("Created authentication with DB authorities: {} and scopes: {}",
                    user.getRoleNames(), scopes);
        }

        // UsernamePasswordAuthenticationToken 생성
        return new UsernamePasswordAuthenticationToken(
                user.getUsername(),
                user.getPassword(),
                allAuthorities);
    }
}
