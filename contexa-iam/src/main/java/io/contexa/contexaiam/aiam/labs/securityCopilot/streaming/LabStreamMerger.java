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


        public Mono<Map<String, String>> waitForAllDiagnosis() {
            return Mono.fromCallable(() -> {
                Map<String, String> results = new HashMap<>();


                for (Map.Entry<String, CompletableFuture<String>> entry : diagnosisFutures.entrySet()) {
                    String labName = entry.getKey();
                    CompletableFuture<String> future = entry.getValue();

                    try {

                        String result = future.get(300, java.util.concurrent.TimeUnit.SECONDS);


                        if (result != null && !result.isEmpty()) {
                            results.put(labName, result);
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

                results.forEach((lab, json) -> {
                    log.error("[{}] [{}]", lab, json);
                });

                return results;
            })

                    ;
        }
    }


    public MergeResult mergeLabStreams(Map<String, Flux<String>> labStreams) {
        Map<String, CompletableFuture<String>> diagnosisFutures = new ConcurrentHashMap<>();
        Map<String, Flux<String>> processedStreams = new HashMap<>();

        labStreams.forEach((labName, stream) -> {
            CompletableFuture<String> diagnosisFuture = new CompletableFuture<>();
            diagnosisFutures.put(labName, diagnosisFuture);
            Flux<String> processedStream = processStreamWithMarkerBuffer(labName, stream, diagnosisFuture);
            processedStreams.put(labName, processedStream);
        });


        Flux<String> mergedStream = Flux.merge(processedStreams.values())
                .doOnSubscribe(sub -> log.info("병합 스트림 시작"))
                .doOnNext(chunk -> {

                    if (log.isDebugEnabled()) {
                        log.debug("병합 스트림 청크: {}",
                                chunk.length() > 50 ? chunk.substring(0, 50) + "..." : chunk);
                    }
                })
                .doOnComplete(() -> log.info("병합 스트림 완료"));

        return new MergeResult(mergedStream, diagnosisFutures);
    }


    private Flux<String> processStreamWithMarkerBuffer(
            String labName,
            Flux<String> stream,
            CompletableFuture<String> diagnosisFuture) {


        final AtomicReference<StringBuilder> markerBuffer = new AtomicReference<>(new StringBuilder());
        final AtomicReference<StringBuilder> jsonBuffer = new AtomicReference<>(new StringBuilder());
        final AtomicBoolean markerDetected = new AtomicBoolean(false);

        return stream
                .<String>handle((chunk, sink) -> {

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


                        String afterMarker = currentBuffer.substring(markerIndex + "###FINAL_RESPONSE###".length());
                        jsonBuffer.get().append(afterMarker);
                        markerBuffer.get().setLength(0);

                    } else if (markerBuffer.get().length() >= 60) {

                        String buffer = markerBuffer.get().toString();
                        int sendLength = Math.min(150, buffer.length() - 50);

                        if (sendLength > 0) {
                            String toSend = buffer.substring(0, sendLength);


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

                    try {

                        if (!markerDetected.get() && markerBuffer.get().length() > 0) {

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


                            String completeJson = JsonExtractor.extractJson(finalData);

                            if (!"{}".equals(completeJson)) {

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

                .timeout(java.time.Duration.ofSeconds(300))
                .onErrorResume(TimeoutException.class, error -> {
                    if (!diagnosisFuture.isDone()) {
                        diagnosisFuture.complete("{}");
                        log.warn("[{}] 타임아웃, 빈 JSON으로 완료", labName);
                    }
                    return Flux.empty();
                });
    }


    private String formatLabOutput(String labName, String content) {

        if (content.contains("[") && content.contains("]")) {
            return content;
        }


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


    private boolean isCompleteCharacter(String str) {
        if (str == null || str.isEmpty()) return true;

        try {

            byte[] bytes = str.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            String reconstructed = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);

            return str.equals(reconstructed);
        } catch (Exception e) {
            return false;
        }
    }


    private int findLastCompleteChar(String str) {
        for (int i = str.length() - 1; i > 0; i--) {
            if (isCompleteCharacter(str.substring(0, i))) {
                return i;
            }
        }
        return 0;
    }
}