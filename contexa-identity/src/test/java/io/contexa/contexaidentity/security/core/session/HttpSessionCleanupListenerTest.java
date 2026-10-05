package io.contexa.contexaidentity.security.core.session;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.security.zerotrust.AbstractZeroTrustSecurityService;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HttpSessionCleanupListenerTest {

    private final AbstractZeroTrustSecurityService zeroTrust = mock(AbstractZeroTrustSecurityService.class);
    private final MfaSessionRepository mfaSessions = mock(MfaSessionRepository.class);
    private final MfaStateMachineService stateMachines = mock(MfaStateMachineService.class);
    private final HttpSession session = mock(HttpSession.class);

    @Test
    void aDestroyedSessionReleasesItsUnfinishedMfaFlowAndItsZeroTrustTracking() {
        when(session.getId()).thenReturn("http-session-1");
        when(mfaSessions.sessionIdOf(session)).thenReturn("mfa-session-1");

        listener().sessionDestroyed(new HttpSessionEvent(session));

        verify(zeroTrust).forgetSession("http-session-1");
        verify(stateMachines).releaseStateMachine("mfa-session-1");
        verify(mfaSessions).forgetSession("mfa-session-1");
    }

    @Test
    void aSessionWithoutAnMfaFlowOnlyForgetsTheZeroTrustTracking() {
        when(session.getId()).thenReturn("http-session-2");

        listener().sessionDestroyed(new HttpSessionEvent(session));

        verify(zeroTrust).forgetSession("http-session-2");
        verify(stateMachines, never()).releaseStateMachine(any());
    }

    @Test
    void aReplacedSessionIdIsForgotten() {
        listener().sessionIdChanged(new HttpSessionEvent(session), "old-session-id");

        verify(zeroTrust).forgetSession("old-session-id");
    }

    private HttpSessionCleanupListener listener() {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("zeroTrust", zeroTrust);
        beans.addBean("mfaSessions", mfaSessions);
        beans.addBean("stateMachines", stateMachines);
        ObjectProvider<ZeroTrustSecurityService> zeroTrustProvider = beans.getBeanProvider(ZeroTrustSecurityService.class);
        ObjectProvider<MfaSessionRepository> mfaProvider = beans.getBeanProvider(MfaSessionRepository.class);
        ObjectProvider<MfaStateMachineService> stateMachineProvider = beans.getBeanProvider(MfaStateMachineService.class);
        return new HttpSessionCleanupListener(zeroTrustProvider, mfaProvider, stateMachineProvider);
    }
}
