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
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import io.contexa.contexacore.autonomous.signal.SecurityEventToken;
import io.contexa.contexacore.autonomous.signal.SecurityEventTokenVerifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Verifies pushed Security Event Tokens (docs/agent A5-8; RFC 8417, RFC 8935, OpenID SSF 1.0) with the keys of the
 * configured transmitters: the token's issuer must be one of them, its signature theirs, its type
 * {@code secevent+jwt}, its audience this receiver, and it must carry events and an identifier.
 */
public class JwtSecurityEventTokenVerifier implements SecurityEventTokenVerifier {

    /** The JOSE type a Security Event Token carries. */
    public static final JOSEObjectType SECEVENT = new JOSEObjectType("secevent+jwt");

    private final Map<String, JwtDecoder> decoders;
    private final String audience;

    /**
     * @param decoders the decoder of each transmitter, by issuer; {@link #typeCustomizer()} lets a decoder accept the
     *                 type of a Security Event Token
     * @param audience this receiver, as the transmitters address it
     */
    public JwtSecurityEventTokenVerifier(Map<String, JwtDecoder> decoders, String audience) {
        this.decoders = Map.copyOf(Objects.requireNonNull(decoders, "decoders"));
        if (!StringUtils.hasText(audience)) {
            throw new IllegalArgumentException("The receiver's audience is required");
        }
        this.audience = audience.trim();
    }

    /** The decoder of a transmitter that publishes its keys at the address. */
    public static JwtDecoder jwksDecoder(String jwksUri) {
        return NimbusJwtDecoder.withJwkSetUri(jwksUri).jwtProcessorCustomizer(typeCustomizer()).build();
    }

    /** Lets a decoder accept the type of a Security Event Token, and only that type. */
    public static Consumer<ConfigurableJWTProcessor<SecurityContext>> typeCustomizer() {
        return processor -> processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(SECEVENT,
                new JOSEObjectType("application/secevent+jwt")));
    }

    @Override
    public SecurityEventToken verify(String token) {
        if (!StringUtils.hasText(token)) {
            throw new InvalidSecurityEventTokenException("invalid_request", "No Security Event Token");
        }
        String issuer;
        try {
            issuer = JWTParser.parse(token.trim()).getJWTClaimsSet().getIssuer();
        } catch (ParseException e) {
            throw new InvalidSecurityEventTokenException("invalid_request", "The token is not a JWT");
        }
        JwtDecoder decoder = issuer != null ? decoders.get(issuer) : null;
        if (decoder == null) {
            throw new InvalidSecurityEventTokenException("invalid_issuer", "The issuer is not a configured transmitter");
        }
        Jwt jwt;
        try {
            jwt = decoder.decode(token.trim());
        } catch (JwtException e) {
            throw new InvalidSecurityEventTokenException("invalid_key", "The token does not verify: " + e.getMessage());
        }
        if (jwt.getAudience() == null || !jwt.getAudience().contains(audience)) {
            throw new InvalidSecurityEventTokenException("invalid_audience", "The token is not addressed to this receiver");
        }
        Object events = jwt.getClaims().get("events");
        if (!(events instanceof Map<?, ?> named) || named.isEmpty() || !StringUtils.hasText(jwt.getId())) {
            throw new InvalidSecurityEventTokenException("invalid_request", "The token carries no events or no jti");
        }
        Map<String, Map<String, Object>> byType = new LinkedHashMap<>();
        named.forEach((type, members) -> byType.put(String.valueOf(type), members instanceof Map<?, ?> map
                ? copy(map) : Map.of()));
        Object subjectId = jwt.getClaims().get("sub_id");
        return new SecurityEventToken(issuer, jwt.getId(), jwt.getIssuedAt(),
                subjectId instanceof Map<?, ?> subject ? copy(subject) : null, byType);
    }

    private static Map<String, Object> copy(Map<?, ?> map) {
        Map<String, Object> copied = new LinkedHashMap<>();
        map.forEach((key, value) -> copied.put(String.valueOf(key), value));
        return copied;
    }
}
