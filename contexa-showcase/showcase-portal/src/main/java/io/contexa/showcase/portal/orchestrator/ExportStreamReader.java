package io.contexa.showcase.portal.orchestrator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.LongSupplier;

/**
 * Reads a streamed export line by line and keeps how far it got over time (deck p.11, P3-BE-02): the delivered count
 * sampled about every {@link #SAMPLE_EVERY_MS} ms from the moment the request was sent, the first and the last line,
 * and whether the engine cut it. A cut is only ever taken from the engine's own in-band marker; a connection that
 * closes without the marker is an interruption, never shown as a block.
 */
public final class ExportStreamReader {

    /** In-band marker the engine writes before it aborts a response (BlockableServletOutputStream). */
    public static final String BLOCK_MARKER = "__CONTEXA_RESPONSE_BLOCKED__:";
    static final long SAMPLE_EVERY_MS = 100;
    private static final int EXCERPT = 2_000;

    /** Delivered items at a moment, in milliseconds since the request was sent. */
    public record Sample(long atMs, int items) {
    }

    /**
     * @param total       items the export announced, or null when the response did not say
     * @param firstLineMs when the first item arrived, null when none did
     * @param endMs       when the stream ended, was cut or broke
     * @param cut         the action the engine wrote with its marker, null when it did not cut
     * @param interrupted the stream broke or ended short of the announced total without the engine's marker
     */
    public record Progress(Integer total, int delivered, Long firstLineMs, long endMs, String cut, boolean interrupted,
                           List<Sample> samples) {
    }

    public record Reading(Progress progress, String head) {
    }

    /** Hears each progress sample while the stream is still being read, for a visitor watching a live run. */
    @FunctionalInterface
    public interface ProgressListener {

        ProgressListener NONE = (atMs, delivered) -> {
        };

        void progress(long atMs, int delivered);
    }

    private ExportStreamReader() {
    }

    /**
     * @param sinceSentMs milliseconds since the request was sent, read at each line
     */
    public static Reading read(InputStream body, Integer total, LongSupplier sinceSentMs) {
        return read(body, total, sinceSentMs, ProgressListener.NONE);
    }

    /**
     * @param sinceSentMs milliseconds since the request was sent, read at each line
     * @param listener    hears every sample as it is taken
     */
    public static Reading read(InputStream body, Integer total, LongSupplier sinceSentMs, ProgressListener listener) {
        int delivered = 0;
        Long firstLineMs = null;
        String cut = null;
        boolean interrupted = false;
        List<Sample> samples = new ArrayList<>();
        long lastSample = 0;
        StringBuilder head = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(BLOCK_MARKER)) {
                    cut = line.substring(BLOCK_MARKER.length()).trim();
                    break;
                }
                if (line.isBlank()) {
                    continue;
                }
                delivered++;
                long now = sinceSentMs.getAsLong();
                if (firstLineMs == null) {
                    firstLineMs = now;
                }
                if (samples.isEmpty() || now - lastSample >= SAMPLE_EVERY_MS) {
                    samples.add(new Sample(now, delivered));
                    lastSample = now;
                    listener.progress(now, delivered);
                }
                if (head.length() < EXCERPT) {
                    head.append(line).append('\n');
                }
            }
        } catch (IOException e) {
            interrupted = cut == null;
        }
        if (cut == null && total != null && delivered < total) {
            interrupted = true;
        }
        long endMs = sinceSentMs.getAsLong();
        if (samples.isEmpty() || samples.get(samples.size() - 1).items() != delivered) {
            samples.add(new Sample(endMs, delivered));
        }
        return new Reading(new Progress(total, delivered, firstLineMs, endMs, cut, interrupted, List.copyOf(samples)),
                head.toString());
    }
}
