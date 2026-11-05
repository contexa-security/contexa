package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacommon.security.context.RequestSecurityContextAttributes;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** W1-9: one failed sign-in is stored once, whichever paths see it in the request. */
class LoginFailureRecordingTest {

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("the failure event, the failure handler and the login policy store one failure once")
    void oneFailureIsStoredOncePerRequest() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        SecurityContextDataStore store = mock(SecurityContextDataStore.class);

        LoginFailureRecording.recordOnce(store, "alice", "203.0.113.10", 1_000L);
        LoginFailureRecording.recordOnce(store, "alice", null, 1_000L);
        LoginFailureRecording.recordOnce(store, " alice ", null, 1_000L);

        verify(store, times(1)).recordLoginFailure(anyString(), any(), anyLong());
        verify(store).recordLoginFailure("alice", "203.0.113.10", 1_000L);
    }

    @Test
    @DisplayName("a name spelled as an internal key is kept off that key")
    void aNameIsStoredUnderThePersonsKey() {
        SecurityContextDataStore store = mock(SecurityContextDataStore.class);

        LoginFailureRecording.recordOnce(store, "console::admin", null, 1_000L);

        verify(store).recordLoginFailure(ZeroTrustUserKey.person("console::admin"), null, 1_000L);
        assertThat(ZeroTrustUserKey.person("console::admin")).isNotEqualTo("console::admin");
    }

    @Test
    @DisplayName("a name no account has, as long as a request can make it, is not kept")
    void anOverlongNameIsNotKept() {
        SecurityContextDataStore store = mock(SecurityContextDataStore.class);

        LoginFailureRecording.recordOnce(store, "x".repeat(LoginFailureRecording.MAX_NAME_LENGTH + 1), "203.0.113.10", 1_000L);

        verify(store).recordLoginFailure(null, "203.0.113.10", 1_000L);
    }

    @Test
    @DisplayName("a failure is kept on the request's clock, the one its window is read on")
    void aFailureIsKeptOnTheRequestsClock() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        Instant observedAt = Instant.parse("2026-09-30T03:14:00Z");
        RequestSecurityContextAttributes.write(request, RequestSecurityContextAttributes.Field.OBSERVED_AT,
                observedAt.toString(), true);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        SecurityContextDataStore store = mock(SecurityContextDataStore.class);

        LoginFailureRecording.recordOnce(store, "alice", null);

        verify(store).recordLoginFailure("alice", null, observedAt.toEpochMilli());
    }

    @Test
    @DisplayName("outside a request every call stores")
    void outsideARequestEveryCallStores() {
        SecurityContextDataStore store = mock(SecurityContextDataStore.class);

        LoginFailureRecording.recordOnce(store, "alice", null, 1_000L);
        LoginFailureRecording.recordOnce(store, "alice", null, 2_000L);

        verify(store, times(2)).recordLoginFailure(anyString(), any(), anyLong());
    }
}
