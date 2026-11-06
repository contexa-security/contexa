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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The token generator an application declared, with Contexa's token checks in front of it. The authorization server asks a
 * token customizer only from the generator it builds itself; an application that declares a generator issues its tokens
 * with its own, and without this none of Contexa's checks would run (a suspended agent would get its token, a token
 * exchange would outlive the token it exchanges). Here the checks run first on the token about to be issued, so a refusal
 * ends the issuance before the application's generator does anything, and nothing it does can swallow it. What a JWT
 * the generator issued lacks of the claims the checks write (the client the token was issued to, the roles, the login
 * facts, the delegation) is added to it, and a limit the checks set on the lifetime (an exchanged token ends with the token
 * it exchanges) is put on it again: that token is then signed again with the authorization server's encoder, once, and
 * only when the claims changed. A claim the generator wrote itself is kept as it wrote it.
 */
@Slf4j
public final class CheckedTokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {

    /** The end of a token while the checks have set no limit on it; any limit they set is an earlier end. */
    private static final Instant NO_LIMIT = Instant.parse("9999-12-31T23:59:59Z");
    private static final String DEVICE_ID = "device_id";
    /** The claims the checks run on start with: they are not claims the checks add. */
    private static final Set<String> SEEDED = Set.of(JwtClaimNames.SUB, JwtClaimNames.IAT, JwtClaimNames.EXP);

    private final OAuth2TokenGenerator<?> application;
    private final ContexaTokenChecks checks;
    private final JwtEncoder encoder;

    public CheckedTokenGenerator(OAuth2TokenGenerator<?> application, ContexaTokenChecks checks, JwtEncoder encoder) {
        Assert.notNull(application, "application cannot be null");
        Assert.notNull(checks, "checks cannot be null");
        Assert.notNull(encoder, "encoder cannot be null");
        this.application = application;
        this.checks = checks;
        this.encoder = encoder;
    }

    /** The generator the application declared. */
    public OAuth2TokenGenerator<?> application() {
        return application;
    }

    @Override
    public OAuth2Token generate(OAuth2TokenContext context) {
        // The tokens the authorization server offers to a customizer: the access token and the ID token.
        if (!offeredToCustomizer(context.getTokenType())) {
            return application.generate(context);
        }
        Authentication principal = context.getPrincipal();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .subject(principal.getName())
                .issuedAt(Instant.now())
                .expiresAt(NO_LIMIT);
        checks.apply(encodingContext(context, principal, claims));
        Map<String, Object> written = claims.build().getClaims();

        OAuth2Token token = application.generate(context);
        return token instanceof Jwt jwt ? withWhatTheChecksWrote(jwt, written) : token;
    }

    private static boolean offeredToCustomizer(OAuth2TokenType type) {
        return OAuth2TokenType.ACCESS_TOKEN.equals(type)
                || (type != null && OidcParameterNames.ID_TOKEN.equals(type.getValue()));
    }

    /** The context the authorization server's own generator would have given the customizer. */
    private static JwtEncodingContext encodingContext(OAuth2TokenContext context, Authentication principal,
                                                      JwtClaimsSet.Builder claims) {
        JwtEncodingContext.Builder builder = JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), claims)
                .registeredClient(context.getRegisteredClient())
                .principal(principal)
                .authorizedScopes(context.getAuthorizedScopes())
                .tokenType(context.getTokenType())
                .authorizationGrantType(context.getAuthorizationGrantType());
        if (context.getAuthorizationServerContext() != null) {
            builder.authorizationServerContext(context.getAuthorizationServerContext());
        }
        if (context.getAuthorization() != null) {
            builder.authorization(context.getAuthorization());
        }
        Authentication grant = context.getAuthorizationGrant();
        if (grant != null) {
            builder.authorizationGrant(grant);
        }
        if (context.hasKey(DEVICE_ID)) {
            builder.put(DEVICE_ID, context.get(DEVICE_ID));
        }
        return builder.build();
    }

    private Jwt withWhatTheChecksWrote(Jwt issued, Map<String, Object> written) {
        Map<String, Object> merged = new LinkedHashMap<>(issued.getClaims());
        boolean changed = false;
        for (Map.Entry<String, Object> claim : written.entrySet()) {
            if (!SEEDED.contains(claim.getKey()) && merged.putIfAbsent(claim.getKey(), claim.getValue()) == null) {
                changed = true;
            }
        }
        Instant limit = written.get(JwtClaimNames.EXP) instanceof Instant end && end.isBefore(NO_LIMIT) ? end : null;
        if (limit != null && (issued.getExpiresAt() == null || issued.getExpiresAt().isAfter(limit))) {
            merged.put(JwtClaimNames.EXP, limit);
            changed = true;
        }
        if (!changed) {
            return issued;
        }
        return encoder.encode(JwtEncoderParameters.from(headerOf(issued), JwtClaimsSet.builder().claims(all -> all.putAll(merged)).build()));
    }

    private static JwsHeader headerOf(Jwt issued) {
        String name = String.valueOf(issued.getHeaders().get("alg"));
        JwsAlgorithm algorithm = SignatureAlgorithm.from(name);
        if (algorithm == null) {
            algorithm = MacAlgorithm.from(name);
        }
        if (algorithm == null) {
            log.error("[OAuth2] The application's token generator issued a token signed with {}, which Contexa cannot sign "
                    + "again to add its claims; the token is not issued.", name);
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token could not be completed", null));
        }
        return JwsHeader.with(algorithm).headers(headers -> headers.putAll(issued.getHeaders())).build();
    }
}
