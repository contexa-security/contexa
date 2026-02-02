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

        if (!jsonStarted.get() && textBuffer.get().toString().contains(StreamingProtocol.JSON_START_MARKER)) {
            jsonStarted.set(true);
            int startIndex = textBuffer.get().toString().indexOf(StreamingProtocol.JSON_START_MARKER);

            String beforeJson = textBuffer.get().substring(0, startIndex);

            String afterJsonMarker = textBuffer.get().substring(startIndex + StreamingProtocol.JSON_START_MARKER.length());
            textBuffer.set(new StringBuilder(afterJsonMarker));
            jsonBuffer.set(new StringBuilder());

            if (!beforeJson.trim().isEmpty()) {
                return Flux.just(StreamingProtocol.STREAMING_MARKER + beforeJson);
            } else {
                return Flux.empty();
            }
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

        if (!jsonStarted.get() || jsonEnded.get()) {
            String currentText = textBuffer.get().toString();
            textBuffer.set(new StringBuilder());

            String cleanedText = currentText
                    .replace(StreamingProtocol.JSON_START_MARKER, "")
                    .replace(StreamingProtocol.JSON_END_MARKER, "");
            if (!cleanedText.trim().isEmpty()) {
                return Flux.just(StreamingProtocol.STREAMING_MARKER + cleanedText);
            } else {
                return Flux.empty();
            }
        }

        return Flux.empty();
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
