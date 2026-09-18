package io.contexa.contexacore.security;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.SecuritySessionProperties;
import io.contexa.contexacore.security.session.InMemorySessionIdResolver;
import jakarta.servlet.http.Cookie;
import io.contexa.contexacore.security.zerotrust.InMemoryZeroTrustSecurityService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AISessionSecurityContextRepositoryInvalidationTest {
    private final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
    private final SecuritySessionProperties sessionProperties = new SecuritySessionProperties();
    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final InMemoryBlockingSignalBroadcaster signals = new InMemoryBlockingSignalBroadcaster();
    private final InMemoryZeroTrustSecurityService service = new InMemoryZeroTrustSecurityService(
            mock(ThreatScoreUtil.class), properties, actions, signals);
    private final AISessionSecurityContextRepository repository = new AISessionSecurityContextRepository(
            new AISecurityContextSupport(properties, service, new InMemorySessionIdResolver(sessionProperties)), null, null);
    private final String user = UUID.randomUUID().toString();

    @Test
    void forcedLogoutRejectsRestoredAuthenticationAndPreservesActorBlock() {
        MockHttpServletRequest request = authenticatedRequest();
        MockHttpSession session = (MockHttpSession) request.getSession(false);
        assertThat(repository.loadDeferredContext(request).get().getAuthentication()).isNotNull();
        actions.saveAction(user, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(user);
        signals.registerBlock(user);
        repository.invalidateAllUserSessions(user, "Controlled forced logout regression");

        DeferredSecurityContext restored = repository.loadDeferredContext(request);

        assertThat(restored.get().getAuthentication()).isNull();
        assertThat(restored.isGenerated()).isTrue();
        assertThat(session.isInvalid()).isTrue();
        assertThat(request.getSession(false)).isNull();
        assertThat(actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(signals.isBlocked(user)).isTrue();
        assertThat(restored.get()).isSameAs(restored.get());
    }

    @Test
    void checkingGeneratedFirstAlsoRejectsInvalidatedAuthentication() {
        MockHttpServletRequest request = authenticatedRequest();
        MockHttpSession session = (MockHttpSession) request.getSession(false);
        service.invalidateSession(session.getId(), user, "Controlled single session invalidation");
        DeferredSecurityContext restored = repository.loadDeferredContext(request);

        assertThat(restored.isGenerated()).isTrue();
        assertThat(restored.get().getAuthentication()).isNull();
        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void validSessionRetainsAuthenticationAndReceivesZeroTrustState() {
        MockHttpServletRequest request = authenticatedRequest();
        MockHttpSession session = (MockHttpSession) request.getSession(false);
        DeferredSecurityContext restored = repository.loadDeferredContext(request);
        SecurityContext context = restored.get();

        assertThat(context.getAuthentication().getName()).isEqualTo(user);
        assertThat(context.getAuthentication().getAuthorities()).extracting("authority")
                .contains("ROLE_USER", ZeroTrustAction.PENDING_ANALYSIS.getGrantedAuthority());
        assertThat(restored.isGenerated()).isFalse();
        assertThat(session.isInvalid()).isFalse();
        assertThat(request.getSession(false)).isSameAs(session);
    }

    @Test
    void anonymousRequestDoesNotCreateSession() {
        properties.setEnabled(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        DeferredSecurityContext restored = repository.loadDeferredContext(request);

        assertThat(restored.get().getAuthentication()).isNull();
        assertThat(restored.isGenerated()).isTrue();
        assertThat(request.getSession(false)).isNull();
    }

    @Test
    void disabledZeroTrustPreservesParentRepositoryBehavior() {
        MockHttpServletRequest request = authenticatedRequest();
        MockHttpSession session = (MockHttpSession) request.getSession(false);
        service.invalidateSession(session.getId(), user, "Controlled disabled mode regression");
        properties.setEnabled(false);

        assertThat(repository.loadDeferredContext(request).get().getAuthentication().getName()).isEqualTo(user);
        assertThat(session.isInvalid()).isFalse();
    }

    private MockHttpServletRequest authenticatedRequest() {
        properties.setEnabled(true);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/regression/protected");
        SecurityContext context = new SecurityContextImpl(new UsernamePasswordAuthenticationToken(
                user, "unused", List.of(new SimpleGrantedAuthority("ROLE_USER"))));
        request.getSession().setAttribute("SPRING_SECURITY_CONTEXT", context);
        request.setCookies(new Cookie(sessionProperties.getCookie().getName(), request.getSession(false).getId()));
        return request;
    }
}
