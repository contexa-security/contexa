package io.contexa.contexacore.autonomous.blocking;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BlockableServletOutputStreamTest {

    @Mock
    private ServletOutputStream delegate;

    @Mock
    private BlockingSignalBroadcaster broadcaster;

    @Mock
    private HttpServletResponse response;

    private BlockableServletOutputStream stream;
    private static final String USER_ID = "testUser";

    @BeforeEach
    void setUp() {
        stream = new BlockableServletOutputStream(delegate, broadcaster, USER_ID, response);
        when(response.isCommitted()).thenReturn(false);
    }

    @Test
    @DisplayName("write(int) passes through when not blocked")
    void writeInt_notBlocked_delegatesToOriginal() throws IOException {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(false);

        // when
        stream.write(65);

        // then
        verify(delegate).write(65);
    }

    @Test
    @DisplayName("write(byte[]) passes through when not blocked")
    void writeByteArray_notBlocked_delegatesToOriginal() throws IOException {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(false);
        byte[] data = "test data".getBytes();

        // when
        stream.write(data);

        // then
        verify(delegate).write(data);
    }

    @Test
    @DisplayName("write(byte[], off, len) passes through when not blocked")
    void writeByteArrayWithOffset_notBlocked_delegatesToOriginal() throws IOException {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(false);
        byte[] data = "test data".getBytes();

        // when
        stream.write(data, 0, 4);

        // then
        verify(delegate).write(data, 0, 4);
    }

    @Test
    @DisplayName("write(int) throws IOException when blocked")
    void writeInt_blocked_throwsIOException() {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(true);

        // when & then
        assertThatThrownBy(() -> stream.write(65))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("blocked");
        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    @DisplayName("write(byte[]) throws IOException when blocked")
    void writeByteArray_blocked_throwsIOException() {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(true);

        // when & then
        assertThatThrownBy(() -> stream.write("data".getBytes()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("blocked");
    }

    @Test
    @DisplayName("Aborted flag prevents redundant isBlocked checks")
    void abortedFlag_preventsRedundantChecks() {
        // given - first call sets aborted=true
        when(broadcaster.isBlocked(USER_ID)).thenReturn(true);

        assertThatThrownBy(() -> stream.write(65))
                .isInstanceOf(IOException.class);

        // when - second call should throw immediately due to aborted flag
        // without calling broadcaster.isBlocked again
        assertThatThrownBy(() -> stream.write(66))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("aborted");
    }

    @Test
    @DisplayName("flush passes through when not blocked")
    void flush_notBlocked_delegatesToOriginal() throws IOException {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(false);

        // when
        stream.flush();

        // then
        verify(delegate).flush();
    }

    @Test
    @DisplayName("flush throws IOException when blocked")
    void flush_blocked_throwsIOException() {
        // given
        when(broadcaster.isBlocked(USER_ID)).thenReturn(true);

        // when & then
        assertThatThrownBy(() -> stream.flush())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("blocked");
    }

    @Test
    @DisplayName("isReady delegates to original stream")
    void isReady_delegatesToOriginal() {
        // given
        when(delegate.isReady()).thenReturn(true);

        // when & then
        assertThat(stream.isReady()).isTrue();
    }
}
