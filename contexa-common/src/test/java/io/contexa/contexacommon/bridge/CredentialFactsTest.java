package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.CredentialFacts;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A2-11 (AG-12f): what an access token says about how the request was authorised, read from the token itself: the
 * kind of credential, the grant its form shows, the client, when it was issued and until when it holds, the actors
 * before the one sending it, and whether it is bound to a key. A session's request carries none of these.
 */
class CredentialFactsTest {

    private static final Instant ISSUED = Instant.parse("2026-10-23T01:00:00Z");
    private final BridgeProperties.Delegation.Token config = new BridgeProperties.Delegation.Token();

    @Test
    void aPersonsTokenIsAUserToken() {
        CredentialFacts facts = CredentialFacts.of(token(claims -> claims
                .subject("alice").claim("client_id", "web-app")), config).orElseThrow();

        assertThat(facts.kind()).isEqualTo(CredentialFacts.USER_TOKEN);
        assertThat(facts.grant()).isNull();
        assertThat(facts.clientId()).isEqualTo("web-app");
        assertThat(facts.issuedAt()).isEqualTo(ISSUED);
        assertThat(facts.expiresAt()).isEqualTo(ISSUED.plusSeconds(1800));
        assertThat(facts.chainDepth()).isZero();
        assertThat(facts.binding()).isNull();
    }

    @Test
    void anExchangedTokenNamesItsActorsAndItsGrant() {
        CredentialFacts facts = CredentialFacts.of(token(claims -> claims
                .subject("alice").claim("client_id", "report-agent")
                .claim("act", Map.of("sub", "report-agent", "act", Map.of("sub", "planner-agent")))), config).orElseThrow();

        assertThat(facts.kind()).isEqualTo(CredentialFacts.DELEGATED_TOKEN);
        assertThat(facts.grant()).isEqualTo(CredentialFacts.GRANT_TOKEN_EXCHANGE);
        assertThat(facts.chainDepth()).isEqualTo(2);
        assertThat(facts.priorActors()).containsExactly("planner-agent");
    }

    @Test
    void aClientsOwnTokenIsAClientCredentialsTokenAndADpopTokenIsBound() {
        CredentialFacts facts = CredentialFacts.of(token(claims -> claims
                .subject("report-agent").claim("client_id", "report-agent")
                .claim("cnf", Map.of("jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"))), config).orElseThrow();

        assertThat(facts.kind()).isEqualTo(CredentialFacts.CLIENT_TOKEN);
        assertThat(facts.grant()).isEqualTo(CredentialFacts.GRANT_CLIENT_CREDENTIALS);
        assertThat(facts.binding()).isEqualTo(CredentialFacts.BINDING_DPOP);
        assertThat(facts.payload()).containsEntry("credentialKind", "CLIENT_TOKEN")
                .containsEntry("credentialGrant", "client_credentials")
                .containsEntry("credentialClientId", "report-agent")
                .containsEntry("credentialIssuedAt", "2026-10-23T01:00:00Z")
                .containsEntry("credentialExpiresAt", "2026-10-23T01:30:00Z")
                .containsEntry("credentialChainDepth", 0)
                .containsEntry("credentialBinding", "DPoP");
    }

    @Test
    void aGrantTheTokenStatesIsKeptAndAnMtlsTokenIsBound() {
        CredentialFacts facts = CredentialFacts.of(token(claims -> claims
                .subject("alice").claim("azp", "mobile").claim("gty", "password")
                .claim("cnf", Map.of("x5t#S256", "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"))), config).orElseThrow();

        assertThat(facts.grant()).isEqualTo("password");
        assertThat(facts.clientId()).isEqualTo("mobile");
        assertThat(facts.binding()).isEqualTo(CredentialFacts.BINDING_MTLS);
    }

    /** The token's times are on the issuer's clock: they travel with when the resource server read the token. */
    @Test
    void theFactsCarryWhenTheResourceServerReadTheToken() {
        Instant read = ISSUED.plusSeconds(120);
        CredentialFacts facts = CredentialFacts.of(token(claims -> claims.subject("alice")), config, read)
                .orElseThrow();

        assertThat(facts.checkedAt()).isEqualTo(read);
        assertThat(facts.payload()).containsEntry(CredentialFacts.CHECKED_AT, "2026-10-23T01:02:00Z");
    }

    @Test
    void aSessionsRequestHasNoCredentialFacts() {
        assertThat(CredentialFacts.of(UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()),
                config)).isEmpty();
        assertThat(CredentialFacts.of(null, config)).isEmpty();
    }

    private static JwtAuthenticationToken token(Consumer<Jwt.Builder> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("token").header("alg", "RS256")
                .issuedAt(ISSUED).expiresAt(ISSUED.plusSeconds(1800));
        claims.accept(builder);
        return new JwtAuthenticationToken(builder.build(), List.of());
    }
}
