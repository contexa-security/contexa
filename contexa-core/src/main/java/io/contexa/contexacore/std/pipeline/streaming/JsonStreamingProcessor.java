package io.contexa.contexacore.std.pipeline.streaming;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

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
                .concatWith(Mono.defer(() -> handleStreamCompletion(jsonStarted, jsonEnded, jsonBuffer, textBuffer)))
                .doOnError(error -> log.error("Error occurred during JSON stream processing", error));
    }

    private Flux<String> processJsonStreaming(String chunk,
                                             AtomicReference<StringBuilder> textBuffer,
                                             AtomicBoolean jsonStarted,
                                             AtomicBoolean jsonEnded,
                                             AtomicReference<StringBuilder> jsonBuffer) {

        textBuffer.get().append(chunk);
        String buffer = textBuffer.get().toString();

        if (!jsonStarted.get() && buffer.contains(StreamingProtocol.JSON_START_MARKER)) {
            jsonStarted.set(true);
            int startIndex = buffer.indexOf(StreamingProtocol.JSON_START_MARKER);

            String beforeJson = buffer.substring(0, startIndex);
            String afterMarker = buffer.substring(startIndex + StreamingProtocol.JSON_START_MARKER.length());

            textBuffer.set(new StringBuilder(afterMarker));
            jsonBuffer.set(new StringBuilder());

            List<String> results = new ArrayList<>();
            if (!beforeJson.trim().isEmpty()) {
                results.add(StreamingProtocol.STREAMING_MARKER + beforeJson);
            }
            results.add(StreamingProtocol.GENERATING_RESULT_MARKER);
            return Flux.fromIterable(results);
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

            } else {
                jsonBuffer.get().append(currentText);
                textBuffer.set(new StringBuilder());

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

    private Mono<String> handleStreamCompletion(AtomicBoolean jsonStarted,
                                                AtomicBoolean jsonEnded,
                                                AtomicReference<StringBuilder> jsonBuffer,
                                                AtomicReference<StringBuilder> textBuffer) {
        if (!jsonStarted.get() || jsonEnded.get()) {
            return Mono.empty();
        }

        String remainingJson = jsonBuffer.get().toString();
        String remainingText = textBuffer.get().toString();

        if (!remainingText.isEmpty()) {
            remainingJson += remainingText;
        }

        remainingJson = removePartialMarkers(remainingJson.trim());

        if (remainingJson.isEmpty()) {
            return Mono.empty();
        }

        String repairedJson = repairJson(remainingJson);
        log.error("Stream completed without JSON_END marker - emitting incomplete JSON, jsonLen={}", repairedJson.length());
        return Mono.just(StreamingProtocol.FINAL_RESPONSE_MARKER + repairedJson);
    }

    private String removePartialMarkers(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return text
                .replace(StreamingProtocol.JSON_START_MARKER, "")
                .replace(StreamingProtocol.JSON_END_MARKER, "")
                .replace(StreamingProtocol.FINAL_RESPONSE_MARKER, "")
                .replace(StreamingProtocol.STREAMING_MARKER, "")
                .replace(StreamingProtocol.GENERATING_RESULT_MARKER, "");
    }

    private String cleanTextChunk(String chunk) {
        if (chunk == null || chunk.isEmpty()) {
            return "";
        }
        return chunk.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
    }

    private String repairJson(String json) {
        if (json == null || json.isEmpty()) {
            return json;
        }

        String repaired = json.trim();

        // Fix missing comma after closing bracket before next key: ]" -> ],"
        repaired = repaired.replaceAll("\\]\\s*\"", "],\"");

        // Fix missing comma after closing brace before next key: }" -> },"
        // But not for the last brace in the JSON
        repaired = repaired.replaceAll("\\}\\s*\"(?!\\s*$)", "},\"");

        // Fix missing comma between array elements: }{ -> },{
        repaired = repaired.replaceAll("\\}\\s*\\{", "},{");

        // Fix missing comma between arrays: ][ -> ],[
        repaired = repaired.replaceAll("\\]\\s*\\[", "],[");

        // Fix missing array close and comma before next key: } }" -> }],"
        // This happens when LLM forgets to close array before next object key
        repaired = repaired.replaceAll("\\}\\s*\\}\\s*\"", "}],\"");

        // Validate and try to fix bracket balance
        repaired = fixBracketBalance(repaired);
        if (!repaired.equals(json.trim())) {
            log.error("JSON repaired: original length={}, repaired length={}", json.length(), repaired.length());
        }

        return repaired;
    }

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
