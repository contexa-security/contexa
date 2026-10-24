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
package io.contexa.contexaidentity.security.signal;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.contexa.contexacore.autonomous.signal.SecurityEventToken;
import io.contexa.contexacore.autonomous.signal.SecurityEventTokenVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent A5-8: a pushed Security Event Token is taken only from a configured transmitter, with its signature, the
 * {@code secevent+jwt} type, this receiver as audience, events and an identifier; anything else is refused with the
 * RFC 8935 error.
 */
class JwtSecurityEventTokenVerifierTest {

    private static final String ISSUER = "https://idp.test";
    private static final String AUDIENCE = "https://contexa.test/receiver";

    private final KeyPair transmitterKey = rsa();
    private final KeyPair otherKey = rsa();
    private final JwtSecurityEventTokenVerifier verifier = new JwtSecurityEventTokenVerifier(Map.of(ISSUER,
            NimbusJwtDecoder.withPublicKey((RSAPublicKey) transmitterKey.getPublic())
                    .jwtProcessorCustomizer(JwtSecurityEventTokenVerifier.typeCustomizer()).build()), AUDIENCE);

    @Test
    void aTransmittersTokenIsVerifiedAndRead() throws Exception {
        SecurityEventToken token = verifier.verify(sign(transmitterKey, JwtSecurityEventTokenVerifier.SECEVENT,
                ISSUER, AUDIENCE, true));

        assertThat(token.issuer()).isEqualTo(ISSUER);
        assertThat(token.jti()).isEqualTo("jti-1");
        assertThat(token.subjectId()).containsEntry("format", "iss_sub").containsEntry("sub", "alice");
        assertThat(token.events()).containsKey(SecurityEventToken.SESSION_REVOKED);
    }

    @Test
    void anyOtherTokenIsRefusedWithItsError() throws Exception {
        assertRefused(sign(otherKey, JwtSecurityEventTokenVerifier.SECEVENT, ISSUER, AUDIENCE, true), "invalid_key");
        assertRefused(sign(transmitterKey, JOSEObjectType.JWT, ISSUER, AUDIENCE, true), "invalid_key");
        assertRefused(sign(transmitterKey, JwtSecurityEventTokenVerifier.SECEVENT, "https://other.test", AUDIENCE,
                true), "invalid_issuer");
        assertRefused(sign(transmitterKey, JwtSecurityEventTokenVerifier.SECEVENT, ISSUER, "https://elsewhere.test",
                true), "invalid_audience");
        assertRefused(sign(transmitterKey, JwtSecurityEventTokenVerifier.SECEVENT, ISSUER, AUDIENCE, false),
                "invalid_request");
        assertRefused("not-a-jwt", "invalid_request");
        assertRefused(" ", "invalid_request");
    }

    private void assertRefused(String token, String error) {
        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOfSatisfying(SecurityEventTokenVerifier.InvalidSecurityEventTokenException.class,
                        e -> assertThat(e.error()).isEqualTo(error));
    }

    private static String sign(KeyPair key, JOSEObjectType type, String issuer, String audience, boolean withEvents)
            throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(List.of(audience))
                .jwtID("jti-1")
                .issueTime(new Date())
                .claim("sub_id", Map.of("format", "iss_sub", "iss", issuer, "sub", "alice"));
        if (withEvents) {
            claims.claim("events", Map.of(SecurityEventToken.SESSION_REVOKED, Map.of("event_timestamp", 1_800_000_000)));
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(type).build(), claims.build());
        jwt.sign(new RSASSASigner(key.getPrivate()));
        return jwt.serialize();
    }

    private static KeyPair rsa() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
