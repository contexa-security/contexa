package io.contexa.contexacore.std.pipeline.streaming;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * JSON 스트리밍 처리기 (구 StreamingProcessor)
 *
 * 단일 책임 원칙 (SRP):
 * - 이 클래스의 책임은 오직 하나, 'Flux<String> 스트림에서 ===JSON시작/끝=== 블록을 파싱'하는 것입니다.
 * - 더 이상 AI 모델 호출에 관여하지 않으며, 순수한 스트림 변환(transform) 역할만 수행합니다.
 */
@Slf4j
public class JsonStreamingProcessor {

    /**
     * 입력 스트림에서 JSON 블록을 파싱하여 처리된 스트림을 반환합니다.
     * @param upstream LLM 클라이언트로부터 받은 원본 데이터 스트림
     * @return JSON 블록이 처리된 데이터 스트림
     */
    public Flux<String> process(Flux<String> upstream) {
        AtomicReference<StringBuilder> textBuffer = new AtomicReference<>(new StringBuilder());
        AtomicBoolean jsonStarted = new AtomicBoolean(false);
        AtomicBoolean jsonEnded = new AtomicBoolean(false);
        AtomicReference<StringBuilder> jsonBuffer = new AtomicReference<>(new StringBuilder());

        return upstream
                .map(this::cleanTextChunk)
                .doOnNext(cleanedChunk -> {
                    Thread currentThread = Thread.currentThread();
//                    log.debug("Current Thread: '{}' (Virtual: {})", currentThread.getName(), currentThread.isVirtual());
                })
                .filter(chunk -> !chunk.trim().isEmpty())
                .flatMap(chunk -> processJsonStreaming(chunk, textBuffer, jsonStarted, jsonEnded, jsonBuffer))
                .filter(text -> !text.isEmpty())
                .doOnNext(outputChunk -> {
                })
                .doOnError(error -> log.error("JSON 스트림 처리 중 오류 발생", error));
    }

    /**
     * JSON 스트리밍 처리 - JSON 마커 제거 (완성형 문장 정제)
     */
    private Flux<String> processJsonStreaming(String chunk,
                                             AtomicReference<StringBuilder> textBuffer,
                                             AtomicBoolean jsonStarted,
                                             AtomicBoolean jsonEnded,
                                             AtomicReference<StringBuilder> jsonBuffer) {
        
        // 버퍼에 청크 추가
        textBuffer.get().append(chunk);

        // JSON 시작 감지
        if (!jsonStarted.get() && textBuffer.get().toString().contains("===JSON시작===")) {
            jsonStarted.set(true);
            int startIndex = textBuffer.get().toString().indexOf("===JSON시작===");
            
            // JSON 시작 전의 텍스트 반환 (스트리밍용 마커 추가)
            String beforeJson = textBuffer.get().substring(0, startIndex);
            
            // JSON 부분만 버퍼에 남기기
            String afterJsonMarker = textBuffer.get().substring(startIndex + "===JSON시작===".length());
            textBuffer.set(new StringBuilder(afterJsonMarker));
            jsonBuffer.set(new StringBuilder());
            
            // 스트리밍용 텍스트임을 명확히 표시
            if (!beforeJson.trim().isEmpty()) {
                return Flux.just("###STREAMING###" + beforeJson);
            } else {
                return Flux.empty();
            }
        }

        // JSON 수집 중
        if (jsonStarted.get() && !jsonEnded.get()) {
            String currentText = textBuffer.get().toString();
            
            // JSON 종료 감지
            if (currentText.contains("===JSON끝===")) {
                jsonEnded.set(true);
                int endIndex = currentText.indexOf("===JSON끝===");
                
                // JSON 컨텐츠 추출
                String jsonContent = currentText.substring(0, endIndex);
                jsonBuffer.get().append(jsonContent);
                
                // 남은 텍스트 처리
                String afterJson = currentText.substring(endIndex + "===JSON끝===".length());
                textBuffer.set(new StringBuilder(afterJson));
                
                // JSON 결과와 남은 텍스트를 별도로 처리
                List<String> results = new ArrayList<>();
                
                // 1. JSON 결과 (진단용)
                results.add("###FINAL_RESPONSE###" + jsonBuffer.get().toString());
                
                // 2. 남은 텍스트 (스트리밍용 마커 추가)
                if (afterJson.trim().length() > 0) {
                    results.add("###STREAMING###" + afterJson.trim());
                }
                
                // 별도 스트림으로 분리하여 전송
                return Flux.fromIterable(results);
            }
            
            // JSON 수집 중이므로 아무것도 반환하지 않음
            return Flux.empty();
        }

        // 일반 텍스트 처리
        if (!jsonStarted.get() || jsonEnded.get()) {
            String currentText = textBuffer.get().toString();
            textBuffer.set(new StringBuilder());
            
            // 스트리밍용 텍스트임을 명확히 표시
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