package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** W1-9: one failed sign-in seen by the failure event and by the failure handler is handled once. */
class LoginPolicyServiceFailureOnceTest {

    @AfterEach
    void clear() {
        LoginPolicyService.clearRequestState();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @SuppressWarnings("unchecked")
    void oneFailureIsCountedAndStoredOnceAcrossTheEventAndTheHandler() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        UserRepository users = mock(UserRepository.class);
        when(users.incrementFailedAttempts("alice")).thenReturn(1);
        when(users.findFailedAttempts("alice")).thenReturn(Optional.of(1));
        PasswordPolicyService policies = mock(PasswordPolicyService.class);
        when(policies.getCurrentPolicy()).thenReturn(mock(PasswordPolicy.class));
        SecurityContextDataStore store = mock(SecurityContextDataStore.class);
        ObjectProvider<SecurityContextDataStore> stores = mock(ObjectProvider.class);
        when(stores.getIfAvailable()).thenReturn(store);
        LoginPolicyService service = new LoginPolicyService(users, mock(LoginAttemptIpRepository.class), policies,
                mock(LoginAttemptIpUpserter.class), stores);

        service.onLoginFailure("alice", "203.0.113.10", "BadCredentialsException", "EVENT");
        service.onLoginFailure("alice");

        verify(users, times(1)).incrementFailedAttempts("alice");
        verify(store, times(1)).recordLoginFailure(anyString(), any(), anyLong());
    }
}
