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
package io.contexa.autoconfigure.identity;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.contexa.contexacommon.properties.AuthContextProperties;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * A1-7 (AG-11b): Contexa's resource server checks a token's issuer and, when audiences are configured, its audience;
 * a token failing either is refused before anything else reads it.
 */
class ResourceServerTokenValidationTest {

    @Test
    void aTokenFromThisIssuerIsAcceptedAndOneFromAnotherIsRefused() {
        Keys keys = keys(new AuthContextProperties());

        assertThat(keys.decoder.decode(keys.token("http://localhost:9000", List.of("default-client"))).getSubject())
                .isEqualTo("alice");
        assertThatThrownBy(() -> keys.decoder.decode(keys.token("https://other-issuer.example", List.of("default-client"))))
                .isInstanceOf(JwtValidationException.class)
                .hasMessageContaining("iss");
    }

    @Test
    void issuerValidationCanBeTurnedOff() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setIssuerValidationEnabled(false);
        Keys keys = keys(properties);

        assertThat(keys.decoder.decode(keys.token("https://other-issuer.example", List.of("default-client")))).isNotNull();
    }

    @Test
    void configuredAudiencesRefuseATokenNamingNoneOfThem() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setAudiences(List.of("orders-api", "default-client"));
        Keys keys = keys(properties);

        assertThat(keys.decoder.decode(keys.token("http://localhost:9000", List.of("default-client")))).isNotNull();
        assertThatThrownBy(() -> keys.decoder.decode(keys.token("http://localhost:9000", List.of("report-bot-client"))))
                .isInstanceOf(JwtValidationException.class)
                .hasMessageContaining("aud");
        assertThatThrownBy(() -> keys.decoder.decode(keys.token("http://localhost:9000", List.of())))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void withoutConfiguredAudiencesTheAudienceIsNotChecked() {
        Keys keys = keys(new AuthContextProperties());

        assertThat(keys.decoder.decode(keys.token("http://localhost:9000", List.of("report-bot-client")))).isNotNull();
    }

    private static Keys keys(AuthContextProperties properties) {
        properties.getOauth2().setClientSecret("internal-secret");
        IdentityOAuth2AutoConfiguration configuration = new IdentityOAuth2AutoConfiguration(
                new TransactionTemplate(mock(PlatformTransactionManager.class)), properties);
        JWKSource<SecurityContext> jwkSource = configuration.jwkSource();
        return new Keys(configuration.jwtEncoder(jwkSource), configuration.jwtDecoder(jwkSource));
    }

    private record Keys(JwtEncoder encoder, JwtDecoder decoder) {

        String token(String issuer, List<String> audience) {
            Instant now = Instant.now();
            JwtClaimsSet.Builder claims = JwtClaimsSet.builder().issuer(issuer).subject("alice")
                    .issuedAt(now).expiresAt(now.plusSeconds(300));
            if (!audience.isEmpty()) {
                claims.audience(audience);
            }
            return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(),
                    claims.build())).getTokenValue();
        }
    }
}
