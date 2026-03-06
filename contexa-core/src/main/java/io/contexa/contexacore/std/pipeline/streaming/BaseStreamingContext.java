package io.contexa.contexacore.std.pipeline.streaming;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Base context for streaming state management.
 * Provides common functionality for tracking streaming state, marker detection,
 * and response accumulation across different streaming implementations.
 *
 * <p>This class is designed to be extended by specific streaming contexts
 * that may add domain-specific functionality such as sentence buffering
 * or UI-specific state management.</p>
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * StreamingProperties properties = new StreamingProperties();
 * BaseStreamingContext context = new BaseStreamingContext(properties);
 *
 * streamFlux.doOnNext(chunk -> {
 *     context.appendChunk(chunk);
 *     if (context.isFinalResponseStarted()) {
 *         // Handle final response
 *     }
 * }).subscribe();
 * }</pre>
 */
@Slf4j
public class BaseStreamingContext {

    private final StreamingProperties properties;
    private final StringBuilder allData;
    private final StringBuilder markerBuffer;
    private final StringBuilder finalResponseData;
    private final AtomicBoolean jsonSent;
    private final AtomicBoolean finalResponseStarted;
    private final AtomicBoolean completed;
    private final int maxMarkerLength;

    public BaseStreamingContext(StreamingProperties properties) {
        this.properties = properties;
        this.allData = new StringBuilder();
        this.markerBuffer = new StringBuilder();
        this.finalResponseData = new StringBuilder();
        this.jsonSent = new AtomicBoolean(false);
        this.finalResponseStarted = new AtomicBoolean(false);
        this.completed = new AtomicBoolean(false);
        this.maxMarkerLength = properties.getFinalResponseMarker().length()
                + properties.getMarkerBufferSize();
    }

    public BaseStreamingContext() {
        this(new StreamingProperties());
    }

    public void appendChunk(String chunk) {
        if (chunk == null) {
            return;
        }

        allData.append(chunk);

        if (!finalResponseStarted.get()) {
            markerBuffer.append(chunk);

            if (markerBuffer.length() > maxMarkerLength) {
                markerBuffer.delete(0, markerBuffer.length() - maxMarkerLength);
            }

            String marker = properties.getFinalResponseMarker();
            if (markerBuffer.toString().contains(marker)) {
                finalResponseStarted.set(true);
            }
        } else {
            finalResponseData.append(chunk);
        }
    }

    public boolean isFinalResponseStarted() {
        return finalResponseStarted.get();
    }

    public boolean isJsonSent() {
        return jsonSent.get();
    }

    public void markJsonSent() {
        jsonSent.set(true);
    }

    public boolean isCompleted() {
        return completed.get();
    }

    public String extractJsonPart() {
        String fullData = allData.toString();
        String marker = properties.getFinalResponseMarker();

        if (fullData.contains(marker)) {
            int markerIndex = fullData.indexOf(marker);
            String jsonPart = fullData.substring(markerIndex);
            return jsonPart;
        }
        return null;
    }

    public StreamingProperties getProperties() {
        return properties;
    }
}
