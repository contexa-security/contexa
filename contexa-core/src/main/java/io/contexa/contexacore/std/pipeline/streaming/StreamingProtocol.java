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
     * Marker indicating an error occurred during streaming.
     * Format: ###ERROR###error message
     */
    public static final String ERROR_MARKER = "###ERROR###";

    /**
     * Marker indicating streaming has started.
     */
    public static final String STREAMING_START_MARKER = "###STREAMING_START###";

    /**
     * Marker indicating streaming has completed successfully.
     */
    public static final String STREAMING_COMPLETE_MARKER = "###STREAMING_COMPLETE###";

    private StreamingProtocol() {
        // Utility class - prevent instantiation
    }
}
