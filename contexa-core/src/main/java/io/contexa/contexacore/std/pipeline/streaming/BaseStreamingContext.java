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

    /**
     * Creates a new streaming context with the specified properties.
     *
     * @param properties the streaming configuration properties
     */
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

    /**
     * Creates a new streaming context with default properties.
     */
    public BaseStreamingContext() {
        this(new StreamingProperties());
    }

    /**
     * Appends a chunk to the streaming context and updates marker detection state.
     * This method handles the detection of the final response marker and
     * appropriately routes data to either the marker buffer or final response buffer.
     *
     * @param chunk the streaming chunk to process
     */
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
//                log.debug("[CONTEXT] FINAL_RESPONSE marker detected! allData length={}", allData.length());
            }
        } else {
            finalResponseData.append(chunk);
//            log.debug("[CONTEXT] Appending to finalResponseData: length={}", finalResponseData.length());
        }
    }

    /**
     * Checks if the final response marker has been detected.
     *
     * @return true if final response has started
     */
    public boolean isFinalResponseStarted() {
        return finalResponseStarted.get();
    }

    /**
     * Checks if JSON response has already been sent.
     *
     * @return true if JSON has been sent
     */
    public boolean isJsonSent() {
        return jsonSent.get();
    }

    /**
     * Marks the JSON response as sent.
     */
    public void markJsonSent() {
        jsonSent.set(true);
    }

    /**
     * Checks if the streaming process has completed.
     *
     * @return true if streaming has completed
     */
    public boolean isCompleted() {
        return completed.get();
    }

    /**
     * Marks the streaming process as completed.
     */
    public void markCompleted() {
        completed.set(true);
    }

    /**
     * Gets all accumulated data from the streaming process.
     *
     * @return the complete accumulated data string
     */
    public String getAllData() {
        return allData.toString();
    }

    /**
     * Gets the final response data accumulated after the marker was detected.
     *
     * @return the final response data string
     */
    public String getFinalResponseData() {
        return finalResponseData.toString();
    }

    /**
     * Extracts the JSON part from the accumulated data, starting from the final response marker.
     *
     * @return the JSON part including the marker, or null if marker not found
     */
    public String extractJsonPart() {
        String fullData = allData.toString();
        String marker = properties.getFinalResponseMarker();

        log.debug("[CONTEXT] extractJsonPart called: allData length={}, contains marker={}",
            fullData.length(), fullData.contains(marker));

        if (fullData.contains(marker)) {
            int markerIndex = fullData.indexOf(marker);
            String jsonPart = fullData.substring(markerIndex);
            log.debug("[CONTEXT] Extracted JSON part: length={}", jsonPart.length());
            log.debug("[CONTEXT] JSON part: {}",jsonPart);
//            log.debug("[CONTEXT] JSON part (last 300): {}",
//                jsonPart.length() > 300 ? "..." + jsonPart.substring(jsonPart.length() - 300) : jsonPart);
            return jsonPart;
        }
//        log.debug("[CONTEXT] No marker found, returning null");
        return null;
    }

    /**
     * Extracts only the JSON content without the marker prefix.
     *
     * @return the JSON content without marker, or null if marker not found
     */
    public String extractJsonContent() {
        String fullData = allData.toString();
        String marker = properties.getFinalResponseMarker();

        if (fullData.contains(marker)) {
            int markerIndex = fullData.indexOf(marker);
            return fullData.substring(markerIndex + marker.length());
        }
        return null;
    }

    /**
     * Gets the streaming properties used by this context.
     *
     * @return the streaming properties
     */
    public StreamingProperties getProperties() {
        return properties;
    }

    /**
     * Resets all streaming state for reuse.
     * This method clears all accumulated data and resets all state flags.
     */
    public void reset() {
        allData.setLength(0);
        markerBuffer.setLength(0);
        finalResponseData.setLength(0);
        jsonSent.set(false);
        finalResponseStarted.set(false);
        completed.set(false);
    }
}
