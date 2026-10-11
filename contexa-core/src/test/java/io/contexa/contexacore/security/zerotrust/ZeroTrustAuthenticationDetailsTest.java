package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
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
}
