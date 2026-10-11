package io.contexa.contexacore.autonomous.store;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

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
    @DisplayName("outside a request every call stores")
    void outsideARequestEveryCallStores() {
        SecurityContextDataStore store = mock(SecurityContextDataStore.class);

        LoginFailureRecording.recordOnce(store, "alice", null, 1_000L);
        LoginFailureRecording.recordOnce(store, "alice", null, 2_000L);

        verify(store, times(2)).recordLoginFailure(anyString(), any(), anyLong());
    }
}
