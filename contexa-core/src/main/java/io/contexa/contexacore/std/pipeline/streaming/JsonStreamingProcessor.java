package io.contexa.contexacore.std.pipeline.streaming;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class JsonStreamingProcessor {

    public Flux<String> process(Flux<String> upstream) {
        AtomicReference<StringBuilder> textBuffer = new AtomicReference<>(new StringBuilder());
        AtomicBoolean jsonStarted = new AtomicBoolean(false);
        AtomicBoolean jsonEnded = new AtomicBoolean(false);
        AtomicReference<StringBuilder> jsonBuffer = new AtomicReference<>(new StringBuilder());

        return upstream
                .map(this::cleanTextChunk)
                .doOnNext(cleanedChunk -> {
                    Thread currentThread = Thread.currentThread();

                })
                .filter(chunk -> !chunk.trim().isEmpty())
                .flatMap(chunk -> processJsonStreaming(chunk, textBuffer, jsonStarted, jsonEnded, jsonBuffer))
                .filter(text -> !text.isEmpty())
                .doOnNext(outputChunk -> {
                })
                .doOnError(error -> log.error("JSON 스트림 처리 중 오류 발생", error));
    }

    private Flux<String> processJsonStreaming(String chunk,
                                             AtomicReference<StringBuilder> textBuffer,
                                             AtomicBoolean jsonStarted,
                                             AtomicBoolean jsonEnded,
                                             AtomicReference<StringBuilder> jsonBuffer) {

        textBuffer.get().append(chunk);

        if (!jsonStarted.get() && textBuffer.get().toString().contains("===JSON시작===")) {
            jsonStarted.set(true);
            int startIndex = textBuffer.get().toString().indexOf("===JSON시작===");

            String beforeJson = textBuffer.get().substring(0, startIndex);

            String afterJsonMarker = textBuffer.get().substring(startIndex + "===JSON시작===".length());
            textBuffer.set(new StringBuilder(afterJsonMarker));
            jsonBuffer.set(new StringBuilder());

            if (!beforeJson.trim().isEmpty()) {
                return Flux.just("###STREAMING###" + beforeJson);
            } else {
                return Flux.empty();
            }
        }

        if (jsonStarted.get() && !jsonEnded.get()) {
            String currentText = textBuffer.get().toString();

            if (currentText.contains("===JSON끝===")) {
                jsonEnded.set(true);
                int endIndex = currentText.indexOf("===JSON끝===");

                String jsonContent = currentText.substring(0, endIndex);
                jsonBuffer.get().append(jsonContent);

                String afterJson = currentText.substring(endIndex + "===JSON끝===".length());
                textBuffer.set(new StringBuilder(afterJson));

                List<String> results = new ArrayList<>();

                results.add("###FINAL_RESPONSE###" + jsonBuffer.get().toString());

                if (afterJson.trim().length() > 0) {
                    results.add("###STREAMING###" + afterJson.trim());
                }

                return Flux.fromIterable(results);
            }

            return Flux.empty();
        }

        if (!jsonStarted.get() || jsonEnded.get()) {
            String currentText = textBuffer.get().toString();
            textBuffer.set(new StringBuilder());

            String cleanedText = currentText.replaceAll("===JSON시작===", "").replaceAll("===JSON끝===", "");
            if (!cleanedText.trim().isEmpty()) {
                return Flux.just("###STREAMING###" + cleanedText);
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
        byte[] bytes = chunk.getBytes(StandardCharsets.UTF_8);
        String decoded = new String(bytes, StandardCharsets.UTF_8);
        return decoded.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
    }
}