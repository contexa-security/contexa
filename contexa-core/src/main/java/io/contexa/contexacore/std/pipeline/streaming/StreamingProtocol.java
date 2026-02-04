package io.contexa.contexacore.std.pipeline.streaming;

/**
 * Constants for streaming pipeline protocol markers.
 * These markers are used to communicate special events in the streaming response.
 */
public final class StreamingProtocol {

    /**
     * Marker indicating the final complete response follows.
     * Format: ###FINAL_RESPONSE###{"json":"response"}
     */
    public static final String FINAL_RESPONSE_MARKER = "###FINAL_RESPONSE###";

    /**
     * Marker prefix for streaming chunks.
     * Format: ###STREAMING###chunk content
     */
    public static final String STREAMING_MARKER = "###STREAMING###";

    /**
     * Marker indicating JSON content starts in streaming response.
     */
    public static final String JSON_START_MARKER = "===JSON_START===";

    /**
     * Marker indicating JSON content ends in streaming response.
     */
    public static final String JSON_END_MARKER = "===JSON_END===";

    /**
     * Marker indicating result generation has started.
     * Sent when JSON_START is detected to notify client that analysis is complete
     * and result data is being generated.
     */
    public static final String GENERATING_RESULT_MARKER = "###GENERATING_RESULT###";

    private StreamingProtocol() {
        // Utility class - prevent instantiation
    }
}
