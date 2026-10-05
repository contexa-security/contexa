package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.portal.orchestrator.ExportStreamReader.Progress;
import io.contexa.showcase.portal.orchestrator.ExportStreamReader.Sample;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import static org.assertj.core.api.Assertions.assertThat;

/** P3-BE-02: a stream is shown as cut only on the engine's own marker, and its exposure is kept over time. */
class ExportStreamReaderTest {

    @Test
    void aCompleteStreamKeepsItsPaceAndIsNotCut() {
        Progress progress = ExportStreamReader.read(lines(25), 25, clock(40, 10)).progress();

        assertThat(progress.delivered()).isEqualTo(25);
        assertThat(progress.cut()).isNull();
        assertThat(progress.interrupted()).isFalse();
        assertThat(progress.firstLineMs()).isEqualTo(40);
        assertThat(progress.samples()).extracting(Sample::items).containsExactly(1, 11, 21, 25);
        assertThat(progress.samples()).extracting(Sample::atMs).containsExactly(40L, 140L, 240L, 290L);
    }

    @Test
    void theEnginesMarkerCutsTheStreamAndNamesItsAction() {
        InputStream body = new SequenceInputStream(lines(7), text("\n" + ExportStreamReader.BLOCK_MARKER + "BLOCK\n"
                + "{\"documentKey\":\"after-the-marker\"}\n"));

        Progress progress = ExportStreamReader.read(body, 4831, clock(40, 10)).progress();

        assertThat(progress.cut()).isEqualTo("BLOCK");
        assertThat(progress.interrupted()).isFalse();
        assertThat(progress.delivered()).isEqualTo(7);
        assertThat(progress.samples().get(progress.samples().size() - 1).items()).isEqualTo(7);
    }

    @Test
    void aConnectionThatBreaksWithoutTheMarkerIsAnInterruptionNotACut() {
        InputStream broken = new SequenceInputStream(lines(3), new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("connection reset");
            }
        });

        Progress progress = ExportStreamReader.read(broken, 4831, clock(40, 10)).progress();

        assertThat(progress.cut()).isNull();
        assertThat(progress.interrupted()).isTrue();
        assertThat(progress.delivered()).isEqualTo(3);
    }

    @Test
    void aStreamThatEndsShortOfItsAnnouncedTotalIsAnInterruption() {
        Progress progress = ExportStreamReader.read(lines(5), 4831, clock(40, 10)).progress();

        assertThat(progress.cut()).isNull();
        assertThat(progress.interrupted()).isTrue();
        assertThat(ExportStreamReader.read(lines(5), null, clock(40, 10)).progress().interrupted()).isFalse();
    }

    private static InputStream lines(int count) {
        StringBuilder text = new StringBuilder();
        for (int i = 1; i <= count; i++) {
            text.append("{\"documentKey\":\"D-").append(i).append("\"}\n");
        }
        return text(text.toString());
    }

    private static InputStream text(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }

    /** The first reading is at {@code first} ms, every later one {@code step} ms after the previous. */
    private static LongSupplier clock(long first, long step) {
        AtomicLong next = new AtomicLong(first);
        return () -> next.getAndAdd(step);
    }
}
