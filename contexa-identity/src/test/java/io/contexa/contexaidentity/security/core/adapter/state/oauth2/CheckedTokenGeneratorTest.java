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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The generator an application declared, with Contexa's token checks in front of it: the checks run first and a refusal
 * ends the issuance, what a JWT lacks of the claims they write is added, and a limit they set on the lifetime holds.
 */
class CheckedTokenGeneratorTest {

    private final RSAKey key = rsaKey();
    /** A key of the application's own: the authorization server does not hold it. */
    private final RSAKey hostKey = rsaKey("host-own-" + UUID.randomUUID());
    private final JwtEncoder hostEncoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(hostKey)));
    private final AtomicReference<String> lastIssued = new AtomicReference<>();
    private final JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
    private final AtomicInteger applicationIssued = new AtomicInteger();
    private final AtomicInteger signedAgain = new AtomicInteger();
    private final JwtEncoder countingEncoder = parameters -> {
        signedAgain.incrementAndGet();
        return encoder.encode(parameters);
    };

    @Test
    void aRefusalOfTheChecksEndsTheIssuanceBeforeTheApplicationsGeneratorDoesAnything() {
        ContexaTokenChecks refusing = context -> {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        };
        CheckedTokenGenerator generator = generator(application(Duration.ofHours(1)), refusing, countingEncoder);

        assertThatThrownBy(() -> generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client")))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, refused ->
                        assertThat(refused.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
        assertThat(applicationIssued).hasValue(0);
    }

    /** The authorization server offers a customizer the access token and the ID token, and nothing else. */
    @Test
    void theChecksAreAskedForAccessTokensAndIdTokensOnly() {
        List<String> asked = new ArrayList<>();
        ContexaTokenChecks checks = context -> asked.add(context.getTokenType().getValue());
        OAuth2TokenGenerator<OAuth2Token> any = context -> {
            applicationIssued.incrementAndGet();
            return new OAuth2RefreshToken(UUID.randomUUID().toString(), Instant.now(), Instant.now().plusSeconds(60));
        };
        CheckedTokenGenerator generator = generator(any, checks, countingEncoder);

        generator.generate(context(OAuth2TokenType.REFRESH_TOKEN, "report-client"));
        generator.generate(context(new OAuth2TokenType("code"), "report-client"));
        assertThat(asked).isEmpty();
        generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"));
        generator.generate(context(new OAuth2TokenType("id_token"), "report-client"));
        assertThat(asked).containsExactly("access_token", "id_token");
        assertThat(applicationIssued).hasValue(4);
    }

    @Test
    void theChecksSeeTheTokenAsTheAuthorizationServersOwnGeneratorWouldHaveShownIt() {
        List<JwtEncodingContext> seen = new ArrayList<>();
        CheckedTokenGenerator generator = generator(application(Duration.ofHours(1)), seen::add, countingEncoder);
        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(client("report-client"))
                .principal(new UsernamePasswordAuthenticationToken("alice", null, List.of()))
                .authorizedScopes(Set.of("reports.read"))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .put("device_id", "device-1")
                .build();

        generator.generate(context);

        assertThat(seen).singleElement().satisfies(given -> {
            assertThat(given.getRegisteredClient().getClientId()).isEqualTo("report-client");
            assertThat(given.getPrincipal().getName()).isEqualTo("alice");
            assertThat(given.getAuthorizedScopes()).containsExactly("reports.read");
            assertThat(given.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
            assertThat(given.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
            assertThat((Object) given.get("device_id")).isEqualTo("device-1");
            assertThat(given.getClaims().build().getClaims()).containsEntry("sub", "alice");
        });
    }

    /** The claims the checks write are on the token; a claim the application wrote itself stays as it wrote it. */
    @Test
    void whatTheChecksWriteIsAddedToTheJwtAndWhatTheApplicationWroteIsKept() {
        ContexaTokenChecks checks = context -> context.getClaims()
                .claim("client_id", context.getRegisteredClient().getClientId())
                .claim("roles", List.of("USER"))
                .claim("tenant", "contexa");
        CheckedTokenGenerator generator = generator(application(Duration.ofHours(1), "tenant", "acme"),
                checks, countingEncoder);

        Jwt issued = (Jwt) generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"));

        assertThat(issued.getClaimAsString("client_id")).isEqualTo("report-client");
        assertThat(issued.getClaimAsStringList("roles")).containsExactly("USER");
        assertThat(issued.getClaimAsString("tenant")).as("the application's own claim is kept").isEqualTo("acme");
        assertThat(issued.getSubject()).isEqualTo("alice");
        assertThat(signedAgain).hasValue(1);
        Jwt verified = decoder().decode(issued.getTokenValue());
        assertThat(verified.getClaimAsString("client_id")).isEqualTo("report-client");
        assertThat(verified.getId()).isEqualTo(issued.getId());
    }

    @Test
    void aLimitTheChecksSetOnTheLifetimeEndsATokenThatWouldOutliveItAndASoonerEndIsLeftAlone() {
        Instant limit = Instant.now().plusSeconds(120).truncatedTo(ChronoUnit.SECONDS);
        ContexaTokenChecks checks = context -> context.getClaims().expiresAt(limit);

        Jwt longLived = (Jwt) generator(application(Duration.ofHours(1)), checks, countingEncoder)
                .generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"));
        assertThat(longLived.getExpiresAt()).isEqualTo(limit);
        assertThat(decoder().decode(longLived.getTokenValue()).getExpiresAt()).isEqualTo(limit);
        assertThat(signedAgain).hasValue(1);

        Jwt shortLived = (Jwt) generator(application(Duration.ofSeconds(30)), checks, countingEncoder)
                .generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"));
        assertThat(shortLived.getExpiresAt()).isBefore(limit);
        assertThat(signedAgain).as("a token that already ends sooner is not signed again").hasValue(1);
    }

    @Test
    void aTokenTheChecksHaveNothingToAddToIsReturnedAsTheApplicationIssuedIt() {
        CheckedTokenGenerator generator = generator(application(Duration.ofHours(1)), context -> { },
                countingEncoder);

        Jwt issued = (Jwt) generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"));

        assertThat(signedAgain).hasValue(0);
        assertThat(issued.getClaimAsString("tenant")).isEqualTo("acme");
    }

    @Test
    void anAccessTokenThatIsNoJwtPassesAfterTheChecksRan() {
        List<String> asked = new ArrayList<>();
        OAuth2AccessToken opaque = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "opaque-value",
                Instant.now(), Instant.now().plusSeconds(60));
        CheckedTokenGenerator generator = generator(context -> opaque,
                context -> asked.add(context.getRegisteredClient().getClientId()), countingEncoder);

        assertThat(generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"))).isSameAs(opaque);
        assertThat(asked).containsExactly("report-client");
    }

    /** What the server's keys cannot verify is not the server's, whatever it says of itself: it is left as it was issued. */
    @Test
    void aTokenOfAnAlgorithmTheServerDoesNotVerifyIsLeftAsItWas() {
        Jwt foreign = Jwt.withTokenValue("foreign")
                .header("alg", "ES999")
                .claim("sub", "alice")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
        CheckedTokenGenerator generator = generator(context -> foreign,
                context -> context.getClaims().claim("client_id", "report-client"), countingEncoder);

        assertThat(generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"))).isSameAs(foreign);
        assertThat(signedAgain).hasValue(0);
    }

    /** A generator of a key of its own says so once in the process, not with every token. */
    @Test
    void aGeneratorWithAKeyOfItsOwnIsSaidOnceInTheProcess() {
        CheckedTokenGenerator.forgetThatTheOtherKeyWasReported();
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        Logger logger = (Logger) LoggerFactory.getLogger(CheckedTokenGenerator.class);
        logged.start();
        logger.addAppender(logged);
        try {
            ContexaTokenChecks checks = context -> context.getClaims().claim("client_id", "report-client");
            CheckedTokenGenerator first = generator(applicationSigningWith(hostEncoder, Duration.ofHours(1)), checks,
                    countingEncoder);
            CheckedTokenGenerator second = generator(applicationSigningWith(hostEncoder, Duration.ofHours(1)), checks,
                    countingEncoder);
            for (int token = 0; token < 3; token++) {
                first.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"));
            }
            second.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"));

            assertThat(logged.list).filteredOn(event -> event.getLevel() == Level.WARN).singleElement()
                    .satisfies(event -> assertThat(event.getFormattedMessage())
                            .contains("key the authorization server does not hold", "resource server does not accept"));
        } finally {
            logger.detachAppender(logged);
        }
    }

    @Test
    void aGeneratorWithTheServersKeyIsNotSaidAtAll() {
        CheckedTokenGenerator.forgetThatTheOtherKeyWasReported();
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        Logger logger = (Logger) LoggerFactory.getLogger(CheckedTokenGenerator.class);
        logged.start();
        logger.addAppender(logged);
        try {
            generator(application(Duration.ofHours(1)), context -> context.getClaims().claim("client_id", "report-client"),
                    countingEncoder).generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"));

            assertThat(logged.list).filteredOn(event -> event.getLevel() == Level.WARN).isEmpty();
        } finally {
            logger.detachAppender(logged);
        }
    }

    /** Keys that cannot be reached cannot tell whose a token is: it is not issued, since an unchecked one could be a way round. */
    @Test
    void aTokenWhoseSignatureCannotBeCheckedBecauseTheKeysAreOutOfReachIsNotIssued() {
        JWKSource<SecurityContext> outOfReach = (selector, context) -> {
            throw new KeySourceException("keys out of reach");
        };
        CheckedTokenGenerator generator = new CheckedTokenGenerator(application(Duration.ofHours(1)),
                context -> context.getClaims().claim("client_id", "report-client"), countingEncoder, outOfReach);

        assertThatThrownBy(() -> generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client")))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, refused -> {
                    assertThat(refused.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
                    assertThat(refused.getError().getDescription()).doesNotContain("keys out of reach");
                });
        assertThat(signedAgain).hasValue(0);
    }

    /**
     * A generator that signs with a key of its own issues tokens Contexa cannot sign again, since it has not the key, and
     * its resource server cannot verify, since it has not the key either. They come back as the generator issued them, the
     * checks having run first; the authorization server's encoder is not asked.
     */
    @Test
    void aTokenSignedWithAKeyOfTheApplicationsOwnIsReturnedAsItWasIssuedAfterTheChecksRan() {
        List<String> asked = new ArrayList<>();
        ContexaTokenChecks checks = context -> {
            asked.add(context.getRegisteredClient().getClientId());
            context.getClaims().claim("client_id", context.getRegisteredClient().getClientId());
        };
        CheckedTokenGenerator generator = generator(applicationSigningWith(hostEncoder, Duration.ofHours(1)), checks,
                countingEncoder);

        Jwt issued = (Jwt) generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"));

        assertThat(asked).containsExactly("report-client");
        assertThat(issued.getTokenValue()).as("the application's token, byte for byte").isEqualTo(lastIssued.get());
        assertThat(issued.getClaims()).doesNotContainKey("client_id");
        assertThat(issued.getHeaders()).containsEntry("kid", hostKey.getKeyID());
        assertThat(signedAgain).as("Contexa has not the key to sign it again").hasValue(0);
    }

    @Test
    void aRefusalOfTheChecksEndsTheIssuanceAlsoWhenTheApplicationSignsWithAKeyOfItsOwn() {
        ContexaTokenChecks refusing = context -> {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        };
        CheckedTokenGenerator generator = generator(applicationSigningWith(hostEncoder, Duration.ofHours(1)), refusing,
                countingEncoder);

        assertThatThrownBy(() -> generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client")))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, refused ->
                        assertThat(refused.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
        assertThat(applicationIssued).hasValue(0);
    }

    /** Whether the token is the authorization server's is told by its signature, not by whether it names a key. */
    @Test
    void aTokenOfTheServersKeyThatNamesNoKeyIsStillTheServersAndIsCompletedAndSignedAgain() {
        ContexaTokenChecks checks = context -> context.getClaims().claim("client_id", "report-client");
        CheckedTokenGenerator generator = generator(context -> signedWithoutKeyId(key), checks, countingEncoder);

        Jwt completed = (Jwt) generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"));

        assertThat(completed.getClaimAsString("client_id")).isEqualTo("report-client");
        assertThat(signedAgain).hasValue(1);
        assertThat(completed.getHeaders()).as("the authorization server chose the key").containsEntry("kid", key.getKeyID());
        assertThat(decoder().decode(completed.getTokenValue()).getClaimAsString("client_id")).isEqualTo("report-client");
    }

    @Test
    void aTokenOfAKeyOfTheApplicationsOwnThatNamesNoKeyIsLeftAsItWasToo() {
        ContexaTokenChecks checks = context -> context.getClaims().claim("client_id", "report-client");
        Jwt unnamed = signedWithoutKeyId(hostKey);
        CheckedTokenGenerator generator = generator(context -> unnamed, checks, countingEncoder);

        assertThat(generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client"))).isSameAs(unnamed);
        assertThat(signedAgain).hasValue(0);
    }

    /** A token of the server's key that cannot be completed is not issued: one without the claims would be a way round the checks. */
    @Test
    void aTokenOfTheServersKeyThatCannotBeSignedAgainIsNotIssued() {
        JwtEncoder failing = parameters -> {
            signedAgain.incrementAndGet();
            throw new JwtEncodingException("no key to sign with");
        };
        ContexaTokenChecks checks = context -> context.getClaims().claim("client_id", "report-client");
        CheckedTokenGenerator generator = generator(application(Duration.ofHours(1)), checks, failing);

        assertThatThrownBy(() -> generator.generate(context(OAuth2TokenType.ACCESS_TOKEN, "report-client")))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, refused -> {
                    assertThat(refused.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
                    assertThat(refused.getError().getDescription()).doesNotContain("no key to sign with");
                });
        assertThat(signedAgain).hasValue(1);
    }

    /** A token signed with the key, its header naming no key. */
    private Jwt signedWithoutKeyId(RSAKey signer) {
        try {
            Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
            JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(3600))).jwtID(UUID.randomUUID().toString()).build();
            SignedJWT signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claims);
            signed.sign(new RSASSASigner(signer));
            return Jwt.withTokenValue(signed.serialize()).header("alg", "RS256").subject("alice").issuedAt(now)
                    .expiresAt(now.plusSeconds(3600)).jti(claims.getJWTID()).build();
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private CheckedTokenGenerator generator(OAuth2TokenGenerator<?> application, ContexaTokenChecks checks,
                                            JwtEncoder signingAgain) {
        return new CheckedTokenGenerator(application, checks, signingAgain, new ImmutableJWKSet<>(new JWKSet(key)));
    }

    private OAuth2TokenGenerator<Jwt> application(Duration lifetime, String... claim) {
        return applicationSigningWith(encoder, lifetime, claim);
    }

    private OAuth2TokenGenerator<Jwt> applicationSigningWith(JwtEncoder signing, Duration lifetime, String... claim) {
        return context -> {
            applicationIssued.incrementAndGet();
            Instant now = Instant.now();
            JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                    .subject(context.getPrincipal().getName())
                    .issuedAt(now)
                    .expiresAt(now.plus(lifetime))
                    .id(UUID.randomUUID().toString())
                    .claim("tenant", "acme");
            for (int i = 0; i + 1 < claim.length; i += 2) {
                claims.claim(claim[i], claim[i + 1]);
            }
            Jwt issued = signing.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims.build()));
            lastIssued.set(issued.getTokenValue());
            return issued;
        };
    }

    private JwtDecoder decoder() {
        try {
            return NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build();
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static OAuth2TokenContext context(OAuth2TokenType type, String clientId) {
        Authentication alice = new UsernamePasswordAuthenticationToken("alice", null, List.of());
        return DefaultOAuth2TokenContext.builder()
                .registeredClient(client(clientId))
                .principal(alice)
                .authorizedScopes(Set.of("reports.read"))
                .tokenType(type)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    private static RegisteredClient client(String clientId) {
        return RegisteredClient.withId(clientId).clientId(clientId)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
    }

    private static RSAKey rsaKey() {
        return rsaKey(UUID.randomUUID().toString());
    }

    private static RSAKey rsaKey(String keyId) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) pair.getPublic()).privateKey((RSAPrivateKey) pair.getPrivate())
                    .keyID(keyId).build();
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
