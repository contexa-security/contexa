package io.contexa.contexacore.security;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.InMemoryZeroTrustSecurityService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class AIOAuth2SecurityContextRepositoryTest {
    final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
    final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    final InMemoryBlockingSignalBroadcaster signals = new InMemoryBlockingSignalBroadcaster();
    final InMemoryZeroTrustSecurityService service = new InMemoryZeroTrustSecurityService(
            mock(ThreatScoreUtil.class), properties, actions, signals);
    final SessionIdResolver resolver = mock(SessionIdResolver.class);
    final AISecurityContextSupport support = new AISecurityContextSupport(properties, service, resolver);
    final AIOAuth2SecurityContextRepository repository = new AIOAuth2SecurityContextRepository(support);
    final String actor = UUID.randomUUID().toString();
    final String jti = UUID.randomUUID().toString();

    @AfterEach void clearContext() { SecurityContextHolder.clearContext(); }

    @Test void pendingAndBlockKeepJwtSubjectTypeDetailsAndOriginalRoles() {
        properties.setEnabled(true);
        JwtAuthenticationToken original = authentication(true);
        Object details = new Object(); original.setDetails(details);
        SecurityContextHolder.getContext().setAuthentication(original);
        repository.applyZeroTrustToCurrentContext(new MockHttpServletRequest());
        JwtAuthenticationToken pending = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        assertThat(pending.getName()).isEqualTo(actor);
        assertThat(pending.getToken()).isSameAs(original.getToken());
        assertThat(pending.getDetails()).isSameAs(details);
        assertThat(pending.getAuthorities()).extracting("authority")
                .contains("ROLE_USER", ZeroTrustAction.PENDING_ANALYSIS.getGrantedAuthority());
        actions.saveAction(actor, ZeroTrustAction.BLOCK, Map.of());
        signals.registerBlock(actor);
        service.invalidateDecisionCache(actor);
        repository.applyZeroTrustToCurrentContext(new MockHttpServletRequest());
        JwtAuthenticationToken blocked = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        assertThat(blocked.getName()).isEqualTo(actor);
        assertThat(blocked.getAuthorities()).extracting("authority").contains(ZeroTrustAction.BLOCK.getGrantedAuthority());
    }

    @Test void invalidatedJwtCannotUseAnotherSessionIdentifierToAuthenticate() throws Exception {
        properties.setEnabled(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession();
        when(resolver.resolve(request)).thenReturn(UUID.randomUUID().toString());
        SecurityContextHolder.getContext().setAuthentication(authentication(true));
        service.invalidateSession(jti, actor, "Controlled regression");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        new AIOAuth2ZeroTrustFilter(repository).doFilter(request, response, chain);
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(chain);
        verify(resolver, never()).resolve(request);
    }

    @Test void jwtWithoutJtiDoesNotBorrowHttpSessionOrResolverIdentity() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession();
        assertThat(support.resolveIdentifier(request, authentication(false))).isNull();
        verifyNoInteractions(resolver);
    }

    @Test void actualSessionTakesPrecedenceOverRequestCarriedIdentifier() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String actual = request.getSession().getId();
        assertThat(support.resolveIdentifier(request, null)).isEqualTo(actual);
        verifyNoInteractions(resolver);
    }

    @Test void noSessionUsesConfiguredResolverWithoutCreatingSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        when(resolver.resolve(request)).thenReturn(jti);
        assertThat(support.resolveIdentifier(request, null)).isEqualTo(jti);
        assertThat(request.getSession(false)).isNull();
    }

    @Test void zeroTrustFailureDoesNotContinueToProtectedResource() {
        AISecurityContextSupport failing = mock(AISecurityContextSupport.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        JwtAuthenticationToken token = authentication(true);
        SecurityContextHolder.getContext().setAuthentication(token);
        when(failing.isEnabled()).thenReturn(true);
        when(failing.isActuallyAuthenticated(token)).thenReturn(true);
        doThrow(new IllegalStateException("Controlled backend failure"))
                .when(failing).applyZeroTrust(any(), eq(actor), isNull(), eq(request));
        FilterChain chain = mock(FilterChain.class);
        assertThatThrownBy(() -> new AIOAuth2ZeroTrustFilter(new AIOAuth2SecurityContextRepository(failing))
                .doFilter(request, new MockHttpServletResponse(), chain)).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(chain);
    }

    @Test void disabledZeroTrustRetainsValidJwtContext() {
        properties.setEnabled(false);
        JwtAuthenticationToken token = authentication(true);
        SecurityContextHolder.getContext().setAuthentication(token);
        service.invalidateSession(jti, actor, "Controlled disabled-mode regression");
        repository.applyZeroTrustToCurrentContext(new MockHttpServletRequest());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(token);
    }

    @Test void nonBearerAuthenticationIsNotReplacedByZeroTrustUserAuthentication() {
        properties.setEnabled(true);
        UsernamePasswordAuthenticationToken client = new UsernamePasswordAuthenticationToken(
                "authorization-server-client", "unused", List.of());
        SecurityContextHolder.getContext().setAuthentication(client);
        repository.applyZeroTrustToCurrentContext(new MockHttpServletRequest());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(client);
        verifyNoInteractions(resolver);
    }

    JwtAuthenticationToken authentication(boolean withJti) {
        Jwt.Builder builder = Jwt.withTokenValue("controlled-unit-token").header("alg", "RS256").subject(actor);
        if (withJti) builder.jti(jti);
        return new JwtAuthenticationToken(builder.build(), List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }
}
