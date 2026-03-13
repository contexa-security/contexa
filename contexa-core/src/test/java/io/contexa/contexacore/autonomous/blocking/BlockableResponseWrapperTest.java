package io.contexa.contexacore.autonomous.blocking;

import jakarta.servlet.ServletOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BlockableResponseWrapperTest {

    @Mock
    private BlockingSignalBroadcaster broadcaster;

    private MockHttpServletResponse mockResponse;
    private BlockableResponseWrapper wrapper;
    private static final String USER_ID = "testUser";

    @BeforeEach
    void setUp() {
        mockResponse = new MockHttpServletResponse();
        wrapper = new BlockableResponseWrapper(mockResponse, broadcaster, USER_ID);
    }

    @Test
    @DisplayName("Not blocked - getOutputStream returns stream normally")
    void getOutputStream_notBlocked_returnsStream() throws IOException {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(false);

        // when
        ServletOutputStream outputStream = wrapper.getOutputStream();

        // then
        assertThat(outputStream).isNotNull();
        assertThat(outputStream).isInstanceOf(BlockableServletOutputStream.class);
    }

    @Test
    @DisplayName("Not blocked - getWriter returns writer normally")
    void getWriter_notBlocked_returnsWriter() throws IOException {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(false);

        // when
        PrintWriter writer = wrapper.getWriter();

        // then
        assertThat(writer).isNotNull();
    }

    @Test
    @DisplayName("Blocked - sendError throws IOException with 403 status")
    void sendError_blocked_throwsIOException() {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(true);

        // when & then
        assertThatThrownBy(() -> wrapper.sendError(500))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("blocked");
    }

    @Test
    @DisplayName("Blocked - sendError with message throws IOException")
    void sendErrorWithMessage_blocked_throwsIOException() {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(true);

        // when & then
        assertThatThrownBy(() -> wrapper.sendError(500, "Internal Error"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("blocked");
    }

    @Test
    @DisplayName("Blocked - sendRedirect throws IOException")
    void sendRedirect_blocked_throwsIOException() {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(true);

        // when & then
        assertThatThrownBy(() -> wrapper.sendRedirect("/login"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("blocked");
    }

    @Test
    @DisplayName("Not blocked - sendError works normally")
    void sendError_notBlocked_worksNormally() throws IOException {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(false);

        // when
        wrapper.sendError(404);

        // then
        assertThat(mockResponse.getStatus()).isEqualTo(404);
    }

    @Test
    @DisplayName("Not blocked - sendRedirect works normally")
    void sendRedirect_notBlocked_worksNormally() throws IOException {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(false);

        // when
        wrapper.sendRedirect("/home");

        // then
        assertThat(mockResponse.getRedirectedUrl()).isEqualTo("/home");
    }

    @Test
    @DisplayName("Blocked - status is set to 403 FORBIDDEN")
    void ensureNotBlocked_blocked_setsForbiddenStatus() {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(true);

        // when & then
        assertThatThrownBy(() -> wrapper.sendError(500))
                .isInstanceOf(IOException.class);
        assertThat(mockResponse.getStatus()).isEqualTo(403);
    }
}
