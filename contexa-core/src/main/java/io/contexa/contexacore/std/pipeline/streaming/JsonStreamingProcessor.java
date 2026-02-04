package io.contexa.contexacore.std.pipeline.streaming;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class JsonStreamingProcessor implements ChunkProcessor {

    private static final String PROCESSOR_TYPE = "json";

    // Maximum marker length: ===JSON_START=== = 16 characters
    private static final int MAX_MARKER_LENGTH = 16;

    @Override
    public Flux<String> process(Flux<String> upstream) {
        AtomicReference<StringBuilder> textBuffer = new AtomicReference<>(new StringBuilder());
        AtomicBoolean jsonStarted = new AtomicBoolean(false);
        AtomicBoolean jsonEnded = new AtomicBoolean(false);
        AtomicReference<StringBuilder> jsonBuffer = new AtomicReference<>(new StringBuilder());

        return upstream
                .map(this::cleanTextChunk)
                .filter(chunk -> !chunk.trim().isEmpty())
                .flatMap(chunk -> processJsonStreaming(chunk, textBuffer, jsonStarted, jsonEnded, jsonBuffer))
                .filter(text -> !text.isEmpty())
                .doOnError(error -> log.error("Error occurred during JSON stream processing", error));
    }

    private Flux<String> processJsonStreaming(String chunk,
                                             AtomicReference<StringBuilder> textBuffer,
                                             AtomicBoolean jsonStarted,
                                             AtomicBoolean jsonEnded,
                                             AtomicReference<StringBuilder> jsonBuffer) {

        textBuffer.get().append(chunk);
        String buffer = textBuffer.get().toString();

        // 1. Detect JSON_START marker (only when jsonStarted=false)
        if (!jsonStarted.get() && buffer.contains(StreamingProtocol.JSON_START_MARKER)) {
            jsonStarted.set(true);
            int startIndex = buffer.indexOf(StreamingProtocol.JSON_START_MARKER);

            String beforeJson = buffer.substring(0, startIndex);
            String afterMarker = buffer.substring(startIndex + StreamingProtocol.JSON_START_MARKER.length());

            textBuffer.set(new StringBuilder(afterMarker));
            jsonBuffer.set(new StringBuilder());

            if (!beforeJson.trim().isEmpty()) {
                return Flux.just(StreamingProtocol.STREAMING_MARKER + beforeJson);
            }
            return Flux.empty();
        }

        if (jsonStarted.get() && !jsonEnded.get()) {
            String currentText = textBuffer.get().toString();

            if (currentText.contains(StreamingProtocol.JSON_END_MARKER)) {
                jsonEnded.set(true);
                int endIndex = currentText.indexOf(StreamingProtocol.JSON_END_MARKER);

                String jsonContent = currentText.substring(0, endIndex);
                jsonBuffer.get().append(jsonContent);

                String afterJson = currentText.substring(endIndex + StreamingProtocol.JSON_END_MARKER.length());
                textBuffer.set(new StringBuilder(afterJson));

                List<String> results = new ArrayList<>();
                results.add(StreamingProtocol.FINAL_RESPONSE_MARKER + jsonBuffer.get().toString());

                if (!afterJson.trim().isEmpty()) {
                    results.add(StreamingProtocol.STREAMING_MARKER + afterJson.trim());
                }

                return Flux.fromIterable(results);
            }

            return Flux.empty();
        }

        String currentText = textBuffer.get().toString();

        int keepFromIndex = findIncompleteMarkerIndex(currentText);

        if (keepFromIndex != -1) {
            String toProcess = currentText.substring(0, keepFromIndex);
            String toKeep = currentText.substring(keepFromIndex);
            textBuffer.set(new StringBuilder(toKeep));

            if (!toProcess.trim().isEmpty()) {
                return Flux.just(StreamingProtocol.STREAMING_MARKER + toProcess);
            }
            return Flux.empty();
        }

        // No marker prefix - process entire buffer
        textBuffer.set(new StringBuilder());
        String cleanedText = currentText
                .replace(StreamingProtocol.JSON_START_MARKER, "")
                .replace(StreamingProtocol.JSON_END_MARKER, "");

        if (!cleanedText.trim().isEmpty()) {
            return Flux.just(StreamingProtocol.STREAMING_MARKER + cleanedText);
        }
        return Flux.empty();
    }

    /**
     * Find index where an incomplete marker might start at the end of the buffer.
     * Returns -1 if no incomplete marker prefix is found.
     *
     * Checks if any suffix of the buffer could be the start of:
     * - ===JSON_START===
     * - ===JSON_END===
     */
    private int findIncompleteMarkerIndex(String text) {
        if (text == null || text.isEmpty()) {
            return -1;
        }

        String startMarker = StreamingProtocol.JSON_START_MARKER;
        String endMarker = StreamingProtocol.JSON_END_MARKER;

        // Check suffixes from longest possible incomplete marker to shortest
        int searchStart = Math.max(0, text.length() - MAX_MARKER_LENGTH + 1);

        for (int i = searchStart; i < text.length(); i++) {
            String suffix = text.substring(i);

            // Check if this suffix could be the beginning of a marker
            if (startMarker.startsWith(suffix) || endMarker.startsWith(suffix)) {
                return i;
            }
        }

        return -1;
    }

    private String cleanTextChunk(String chunk) {
        if (chunk == null || chunk.isEmpty()) {
            return "";
        }
        return chunk.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
    }

    @Override
    public String getProcessorType() {
        return PROCESSOR_TYPE;
    }
}
