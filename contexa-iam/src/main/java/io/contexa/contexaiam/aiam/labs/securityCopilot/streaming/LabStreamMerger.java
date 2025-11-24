package io.contexa.contexaiam.aiam.labs.securityCopilot.streaming;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class LabStreamMerger {

    @Data
    public static class MergeResult {
        private final Flux<String> mergedStream;
        private final Map<String, CompletableFuture<String>> diagnosisFutures;
        private static final Scheduler VIRTUAL_SCHEDULER = Schedulers.fromExecutor(Executors.newVirtualThreadPerTaskExecutor());

        /**
         * 모든 진단 결과를 기다림
         */
        public Mono<Map<String, String>> waitForAllDiagnosis() {
            return Mono.fromCallable(() -> {
                Map<String, String> results = new HashMap<>();

                // 각 Future를 개별적으로 처리
                for (Map.Entry<String, CompletableFuture<String>> entry : diagnosisFutures.entrySet()) {
                    String labName = entry.getKey();
                    CompletableFuture<String> future = entry.getValue();

                    try {
                        // Future가 완료될 때까지 대기 (최대 5분)
                        String result = future.get(300, java.util.concurrent.TimeUnit.SECONDS);

                        // 결과 검증
                        if (result != null && !result.isEmpty()) {
                            results.put(labName, result);
                            log.info("[{}] 진단 결과 수집 성공 - 길이: {}", labName, result.length());
                            log.info("Result [{}] ",result);

                            // 디버깅: 결과의 마지막 100자 확인
                            if (result.length() > 100) {
                                String tail = result.substring(result.length() - 100);
                                log.debug("[{}] 결과 끝부분: {}", labName, tail);
                            }
                        } else {
                            log.warn("[{}] 빈 결과", labName);
                            results.put(labName, "{}");
                        }
                    } catch (Exception e) {
                        log.error("[{}] 결과 수집 실패: {}", labName, e.getMessage());
                        results.put(labName, "{}");
                    }
                }

                log.info("전체 진단 결과 수집 완료 - 총 {} 개 Lab", results.size());

                // 최종 결과 검증
                results.forEach((lab, json) -> {
                        log.error("[{}] [{}]", lab, json);
                });

                return results;
            })
//                    .subscribeOn(MergeResult.VIRTUAL_SCHEDULER)
                    ;
        }
    }

    /**
     * 간소화된 병합 - 실시간성 우선
     */
    public MergeResult mergeLabStreams(Map<String, Flux<String>> labStreams) {
        log.info("🔀 Lab 스트림 병합 시작: {} 개", labStreams.size());

        Map<String, CompletableFuture<String>> diagnosisFutures = new ConcurrentHashMap<>();
        Map<String, Flux<String>> processedStreams = new HashMap<>();

        labStreams.forEach((labName, stream) -> {
            CompletableFuture<String> diagnosisFuture = new CompletableFuture<>();
            diagnosisFutures.put(labName, diagnosisFuture);

            // 마커 버퍼 방식으로 변경 + Virtual Thread 적용
            Flux<String> processedStream = processStreamWithMarkerBuffer(labName, stream, diagnosisFuture);

            processedStreams.put(labName, processedStream);
        });

        // 단순 병합 - 우선순위 없이 실시간 전달
        Flux<String> mergedStream = Flux.merge(processedStreams.values())
                .doOnSubscribe(sub -> log.info("병합 스트림 시작"))
                .doOnNext(chunk -> {
                    // 스트림 데이터 흐름 확인을 위한 로깅 (구독하지 않고 로깅만)
                    if (log.isDebugEnabled()) {
                        log.debug("병합 스트림 청크: {}",
                                chunk.length() > 50 ? chunk.substring(0, 50) + "..." : chunk);
                    }
                })
                .doOnComplete(() -> log.info("병합 스트림 완료"));

        return new MergeResult(mergedStream, diagnosisFutures);
    }

    /**
     * 마커 버퍼를 사용한 스트림 처리
     */
    private Flux<String> processStreamWithMarkerBuffer(
            String labName,
            Flux<String> stream,
            CompletableFuture<String> diagnosisFuture) {

        // 상태 변수들은 기존 구조를 그대로 사용합니다.
        final AtomicReference<StringBuilder> markerBuffer = new AtomicReference<>(new StringBuilder());
        final AtomicReference<StringBuilder> jsonBuffer = new AtomicReference<>(new StringBuilder());
        final AtomicBoolean markerDetected = new AtomicBoolean(false);

        return stream
                .<String>handle((chunk, sink) -> {
                    // 스트리밍 로직은 정상 동작하므로 그대로 유지합니다.
                    if (markerDetected.get()) {
                        jsonBuffer.get().append(chunk);
                        return;
                    }

                    markerBuffer.get().append(chunk);
                    String currentBuffer = markerBuffer.get().toString();
                    int markerIndex = currentBuffer.indexOf("###FINAL_RESPONSE###");

                    if (markerIndex != -1) {
                        markerDetected.set(true);
                        log.info("[{}] FINAL_RESPONSE 마커 감지", labName);

                        String beforeMarker = currentBuffer.substring(0, markerIndex);
                        if (!beforeMarker.isEmpty()) {
                            sink.next(formatLabOutput(labName, beforeMarker));
                        }

                        // 마커 이후 전체 데이터를 JSON 버퍼에 추가
                        String afterMarker = currentBuffer.substring(markerIndex + "###FINAL_RESPONSE###".length());
                        jsonBuffer.get().append(afterMarker);
                        markerBuffer.get().setLength(0);

                    } else if (markerBuffer.get().length() >= 60) {  // 버퍼 크기를 더 크게
                        // 단순히 앞에서 150자를 전송 (한글 3바이트 * 50자 = 150바이트)
                        String buffer = markerBuffer.get().toString();
                        int sendLength = Math.min(150, buffer.length() - 50);

                        if (sendLength > 0) {
                            String toSend = buffer.substring(0, sendLength);

                            // 마지막 문자가 온전한지 확인
                            if (!isCompleteCharacter(toSend)) {
                                sendLength = findLastCompleteChar(toSend);
                                toSend = buffer.substring(0, sendLength);
                            }

                            markerBuffer.get().delete(0, sendLength);

                            if (!toSend.trim().isEmpty()) {
                                sink.next(formatLabOutput(labName, toSend));
                            }
                        }
                    }
                })
                .doOnComplete(() -> {
                    // ★★★ 최종 데이터 검증 로직 ★★★
                    try {
                        // 남은 버퍼 데이터 처리
                        if (!markerDetected.get() && markerBuffer.get().length() > 0) {
                            // 남은 버퍼에서 마커 재확인
                            String remaining = markerBuffer.get().toString();
                            int markerIndex = remaining.indexOf("###FINAL_RESPONSE###");
                            if (markerIndex != -1) {
                                markerDetected.set(true);
                                String afterMarker = remaining.substring(markerIndex + "###FINAL_RESPONSE###".length());
                                jsonBuffer.get().append(afterMarker);
                            }
                        }

                        if (markerDetected.get()) {
                            String finalData = jsonBuffer.get().toString();

                            // JsonExtractor를 사용해 100% 완성된 JSON만 추출
                            String completeJson = JsonExtractor.extractJson(finalData);

                            if (!"{}".equals(completeJson)) {
                                // 마커 없이 순수한 JSON만 Future에 전달
                                diagnosisFuture.complete(completeJson);
                                log.info("[{}] 100% 완성된 진단 결과 수집 완료.", labName);
                            } else {
                                log.error("[{}] 최종 데이터에서 완성된 JSON을 찾지 못했습니다.", labName);
                                diagnosisFuture.complete("{}");
                            }
                        } else if (!diagnosisFuture.isDone()) {
                            log.warn("[{}] 스트림이 완료되었지만 FINAL_RESPONSE 마커를 찾지 못했습니다.", labName);
                            diagnosisFuture.complete("{}");
                        }
                    } catch (Exception e) {
                        log.error("[{}] 완료 처리 중 오류", labName, e);
                        diagnosisFuture.completeExceptionally(e);
                    }
                })
                .doOnError(error -> {
                    log.error("[{}] 스트림 오류", labName, error);
                    diagnosisFuture.completeExceptionally(error);
                })
                // 타임아웃 설정
                .timeout(java.time.Duration.ofSeconds(300))
                .onErrorResume(TimeoutException.class, error -> {
                    if (!diagnosisFuture.isDone()) {
                        diagnosisFuture.complete("{}");
                        log.warn("[{}] 타임아웃, 빈 JSON으로 완료", labName);
                    }
                    return Flux.empty();
                });
    }

    /**
     * Lab 출력 포맷팅
     */
    private String formatLabOutput(String labName, String content) {
        // 이미 포맷팅된 경우 그대로 반환
        if (content.contains("[") && content.contains("]")) {
            return content;
        }

        // Lab 이름 태그 추가
        String displayName = getDisplayName(labName);
        return String.format("[%s] %s", displayName, content);
    }

    private String getDisplayName(String labName) {
        return switch (labName) {
            case "StudioQuery" -> "권한분석";
            case "RiskAssessment" -> "위험평가";
            case "PolicyGeneration" -> "정책생성";
            default -> labName;
        };
    }

    /**
     * 문자열이 완전한 문자로 끝나는지 확인
     */
    private boolean isCompleteCharacter(String str) {
        if (str == null || str.isEmpty()) return true;

        try {
            // 문자열을 바이트로 변환했다가 다시 문자열로 변환
            byte[] bytes = str.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            String reconstructed = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
            // 원본과 같으면 완전한 문자
            return str.equals(reconstructed);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 마지막 완전한 문자의 위치 찾기
     */
    private int findLastCompleteChar(String str) {
        for (int i = str.length() - 1; i > 0; i--) {
            if (isCompleteCharacter(str.substring(0, i))) {
                return i;
            }
        }
        return 0;
    }
}