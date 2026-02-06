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

        log.debug("content={}", chunk.length() > 100 ? chunk.substring(0, 100) + "..." : chunk);

        textBuffer.get().append(chunk);
        String buffer = textBuffer.get().toString();

//        log.debug("[STATE] jsonStarted={}, jsonEnded={}, bufferLen={}, jsonBufferLen={}",
//            jsonStarted.get(), jsonEnded.get(), buffer.length(), jsonBuffer.get().length());

        if (!jsonStarted.get() && buffer.contains(StreamingProtocol.JSON_START_MARKER)) {
            jsonStarted.set(true);
            int startIndex = buffer.indexOf(StreamingProtocol.JSON_START_MARKER);

            String beforeJson = buffer.substring(0, startIndex);
            String afterMarker = buffer.substring(startIndex + StreamingProtocol.JSON_START_MARKER.length());

            textBuffer.set(new StringBuilder(afterMarker));
            jsonBuffer.set(new StringBuilder());

//            log.debug("[JSON_START] detected at index={}, beforeJson length={}, afterMarker length={}",
//                startIndex, beforeJson.length(), afterMarker.length());

            List<String> results = new ArrayList<>();
            if (!beforeJson.trim().isEmpty()) {
                results.add(StreamingProtocol.STREAMING_MARKER + beforeJson);
            }
            results.add(StreamingProtocol.GENERATING_RESULT_MARKER);
            return Flux.fromIterable(results);
        }

        if (jsonStarted.get() && !jsonEnded.get()) {
            String currentText = textBuffer.get().toString();

//            log.debug("[JSON_ACCUMULATING] currentText length={}, contains END_MARKER={}",
//                currentText.length(), currentText.contains(StreamingProtocol.JSON_END_MARKER));

            if (currentText.contains(StreamingProtocol.JSON_END_MARKER)) {
                jsonEnded.set(true);
                int endIndex = currentText.indexOf(StreamingProtocol.JSON_END_MARKER);

                String jsonContent = currentText.substring(0, endIndex);
                jsonBuffer.get().append(jsonContent);

                String afterJson = currentText.substring(endIndex + StreamingProtocol.JSON_END_MARKER.length());
                textBuffer.set(new StringBuilder(afterJson));

                List<String> results = new ArrayList<>();
                String rawJson = jsonBuffer.get().toString().trim();

                results.add(StreamingProtocol.FINAL_RESPONSE_MARKER + rawJson);

                if (!afterJson.trim().isEmpty()) {
                    results.add(StreamingProtocol.STREAMING_MARKER + afterJson.trim());
                }

                return Flux.fromIterable(results);
            }

            int keepFromIndex = findIncompleteMarkerIndex(currentText);

            if (keepFromIndex != -1) {
                String toAccumulate = currentText.substring(0, keepFromIndex);
                String toKeep = currentText.substring(keepFromIndex);

                if (!toAccumulate.isEmpty()) {
                    jsonBuffer.get().append(toAccumulate);
                }
                textBuffer.set(new StringBuilder(toKeep));

//                log.debug("[JSON_BUFFER] partial accumulate, jsonBufferLen={}, keeping={}",
//                    jsonBuffer.get().length(), toKeep);
            } else {
                jsonBuffer.get().append(currentText);
                textBuffer.set(new StringBuilder());

//                log.debug("[JSON_BUFFER] full accumulate, total jsonBuffer length={}", jsonBuffer.get().length());
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

        int maxBufferSize = 100;
        if (currentText.length() > maxBufferSize) {
            String toProcess = currentText.substring(0, currentText.length() - MAX_MARKER_LENGTH);
            String toKeep = currentText.substring(currentText.length() - MAX_MARKER_LENGTH);
            textBuffer.set(new StringBuilder(toKeep));

            String cleanedText = toProcess
                    .replace(StreamingProtocol.JSON_START_MARKER, "")
                    .replace(StreamingProtocol.JSON_END_MARKER, "");

            if (!cleanedText.trim().isEmpty()) {
                return Flux.just(StreamingProtocol.STREAMING_MARKER + cleanedText);
            }
            return Flux.empty();
        }

        // Buffer size is small - keep accumulating for marker detection
        // Only clear and output if no marker possibility
        if (currentText.length() <= MAX_MARKER_LENGTH) {
            return Flux.empty();
        }

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

        int searchStart = Math.max(0, text.length() - MAX_MARKER_LENGTH + 1);

        for (int i = searchStart; i < text.length(); i++) {
            String suffix = text.substring(i);
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

    /**
     * Repair common JSON syntax errors from LLM output.
     * Fixes missing commas between array elements and object properties.
     */
    private String repairJson(String json) {
        if (json == null || json.isEmpty()) {
            return json;
        }

        log.debug("[REPAIR_JSON] Input JSON (first 500 chars): {}",
            json.length() > 500 ? json.substring(0, 500) + "..." : json);
        log.debug("[REPAIR_JSON] Input JSON (last 500 chars): {}",
            json.length() > 500 ? "..." + json.substring(json.length() - 500) : json);

        String repaired = json.trim();

        // Fix missing comma after closing bracket before next key: ]" -> ],"
        String before1 = repaired;
        repaired = repaired.replaceAll("\\]\\s*\"", "],\"");
        if (!before1.equals(repaired)) {
            log.debug("[REPAIR_JSON] Applied pattern 1: ]\" -> ],\"");
        }

        // Fix missing comma after closing brace before next key: }" -> },"
        // But not for the last brace in the JSON
        String before2 = repaired;
        repaired = repaired.replaceAll("\\}\\s*\"(?!\\s*$)", "},\"");
        if (!before2.equals(repaired)) {
            log.debug("[REPAIR_JSON] Applied pattern 2: }\" -> },\"");
        }

        // Fix missing comma between array elements: }{ -> },{
        String before3 = repaired;
        repaired = repaired.replaceAll("\\}\\s*\\{", "},{");
        if (!before3.equals(repaired)) {
            log.debug("[REPAIR_JSON] Applied pattern 3: }{ -> },{");
        }

        // Fix missing comma between arrays: ][ -> ],[
        String before4 = repaired;
        repaired = repaired.replaceAll("\\]\\s*\\[", "],[");
        if (!before4.equals(repaired)) {
            log.debug("[REPAIR_JSON] Applied pattern 4: ][ -> ],[");
        }

        // Fix missing array close and comma before next key: } }" -> }],"
        // This happens when LLM forgets to close array before next object key
        String before5 = repaired;
        repaired = repaired.replaceAll("\\}\\s*\\}\\s*\"", "}],\"");
        if (!before5.equals(repaired)) {
            log.debug("[REPAIR_JSON] Applied pattern 5: } }\" -> }],\"");
        }

        // Validate and try to fix bracket balance
        String before6 = repaired;
        repaired = fixBracketBalance(repaired);
        if (!before6.equals(repaired)) {
            log.debug("[REPAIR_JSON] Applied bracket balance fix");
        }

        log.debug("[REPAIR_JSON] Output JSON (first 500 chars): {}",
            repaired.length() > 500 ? repaired.substring(0, 500) + "..." : repaired);

        if (!repaired.equals(json.trim())) {
            log.error("JSON repaired: original length={}, repaired length={}", json.length(), repaired.length());
        }

        return repaired;
    }

    /**
     * Fix unbalanced brackets in JSON.
     */
    private String fixBracketBalance(String json) {
        int braceCount = 0;
        int bracketCount = 0;

        for (char c : json.toCharArray()) {
            if (c == '{') braceCount++;
            else if (c == '}') braceCount--;
            else if (c == '[') bracketCount++;
            else if (c == ']') bracketCount--;
        }

        StringBuilder result = new StringBuilder(json);

        // Add missing closing brackets
        while (bracketCount > 0) {
            result.append("]");
            bracketCount--;
        }

        // Add missing closing braces
        while (braceCount > 0) {
            result.append("}");
            braceCount--;
        }

        return result.toString();
    }

    @Override
    public String getProcessorType() {
        return PROCESSOR_TYPE;
    }
}
