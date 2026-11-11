package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The Zero Trust adjusted authentication keeps the details of the login it replaces, where the login facts live (W1-4).
 */
class ZeroTrustAuthenticationDetailsTest {

    @Test
    void theAdjustedAuthenticationKeepsTheLoginDetails() {
        String user = UUID.randomUUID().toString();
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setEnabled(true);
        InMemoryZeroTrustSecurityService security = new InMemoryZeroTrustSecurityService(
                mock(ThreatScoreUtil.class), properties, new InMemoryZeroTrustActionRepository(),
                new InMemoryBlockingSignalBroadcaster());
        UsernamePasswordAuthenticationToken login = new UsernamePasswordAuthenticationToken(
                user, "unused", List.of(new SimpleGrantedAuthority("ROLE_USER")));
        Map<String, Object> details = Map.of("authenticationType", "PASSWORD", "mfaCompleted", false);
        login.setDetails(details);
        SecurityContextImpl context = new SecurityContextImpl(login);

        security.applyZeroTrustToContext(context, user, null, new MockHttpServletRequest("GET", "/protected"));

        assertThat(context.getAuthentication()).isInstanceOf(ZeroTrustAuthenticationToken.class);
        assertThat(((ZeroTrustAuthenticationToken) context.getAuthentication()).getAction())
                .isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(context.getAuthentication().getDetails()).isSameAs(details);
    }

    /**
     * A passkey sign-in names its user itself, and its principal is a user entity that is no UserDetails,
     * AuthenticatedPrincipal or Principal: a replacement that works the name out from the principal gave the entity's
     * object string, and the session was then no longer the user's for what is kept by name.
     */
    @Test
    void theAdjustedAuthenticationKeepsTheNameOfTheSignInItReplaces() {
        String user = UUID.randomUUID().toString();
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setEnabled(true);
        InMemoryZeroTrustSecurityService security = new InMemoryZeroTrustSecurityService(
                mock(ThreatScoreUtil.class), properties, new InMemoryZeroTrustActionRepository(),
                new InMemoryBlockingSignalBroadcaster());
        Object userEntity = new Object();
        AbstractAuthenticationToken passkeySignIn = new AbstractAuthenticationToken(
                List.of(new SimpleGrantedAuthority("ROLE_USER"))) {
            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public Object getPrincipal() {
                return userEntity;
            }

            @Override
            public String getName() {
                return user;
            }
        };
        passkeySignIn.setAuthenticated(true);
        SecurityContextImpl context = new SecurityContextImpl(passkeySignIn);

        security.applyZeroTrustToContext(context, user, null, new MockHttpServletRequest("GET", "/protected"));

        assertThat(context.getAuthentication()).isInstanceOf(ZeroTrustAuthenticationToken.class);
        assertThat(context.getAuthentication().getPrincipal()).isSameAs(userEntity);
        assertThat(context.getAuthentication().getName()).isEqualTo(user);
    }

    @Test
    void aTokenGivenNoNameWorksItOutFromThePrincipalAsBefore() {
        ZeroTrustAuthenticationToken ofAName = new ZeroTrustAuthenticationToken(
                "alice", null, List.of(), 0.9, 0.1, ZeroTrustAction.ALLOW);

        assertThat(ofAName.getName()).isEqualTo("alice");
    }
}
