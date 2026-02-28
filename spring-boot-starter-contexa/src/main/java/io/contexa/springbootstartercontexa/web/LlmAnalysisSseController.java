/*
package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.springbootstartercontexa.event.LlmAnalysisEventPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.security.Principal;
import java.util.Map;

*/
/**
 * LLM 분석 SSE 컨트롤러
 *
 * TIPS 데모용 실시간 LLM 분석 과정을 클라이언트에 스트리밍합니다.
 * Server-Sent Events (SSE)를 사용하여 단방향 실시간 통신을 제공합니다.
 *
 * 엔드포인트:
 * - GET /api/sse/llm-analysis : SSE 스트림 구독
 * - GET /api/sse/llm-analysis/user : 사용자별 SSE 스트림 구독
 * - GET /api/sse/status : 현재 구독자 상태 조회
 *
 * @author contexa
 * @since TIPS Demo v1.0
 *//*

@RestController
@RequestMapping("/api/sse")
@RequiredArgsConstructor
@Slf4j
public class LlmAnalysisSseController {

    private final LlmAnalysisEventPublisher eventPublisher;

    */
/**
     * LLM 분석 이벤트 SSE 스트림 구독 (전체)
     *
     * 모든 LLM 분석 이벤트를 브로드캐스트로 수신합니다.
     * TIPS 데모에서 실시간 분석 과정 시각화에 사용됩니다.
     *
     * 이벤트 타입:
     * - CONTEXT_COLLECTED: 컨텍스트 수집 완료
     * - LAYER1_START: Layer1 분석 시작
     * - LAYER1_COMPLETE: Layer1 분석 완료 (action, riskScore, confidence 포함)
     * - LAYER2_START: Layer2 에스컬레이션
     * - LAYER2_COMPLETE: Layer2 분석 완료
     * - DECISION_APPLIED: 최종 결정 적용
     *
     * @return SseEmitter SSE 스트림
     *//*

    @GetMapping(value = "/llm-analysis", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter subscribeToLlmAnalysis() {
        log.info("[LlmAnalysisSseController] 새 SSE 구독 요청 (전체)");
        return eventPublisher.addEmitter();
    }

    */
/**
     * LLM 분석 이벤트 SSE 스트림 구독 (사용자별)
     *
     * 특정 사용자의 LLM 분석 이벤트만 수신합니다.
     * 인증된 사용자의 경우 자동으로 Principal에서 사용자 ID를 추출합니다.
     *
     * @param principal 인증된 사용자 정보
     * @return SseEmitter SSE 스트림
     *//*

    @GetMapping(value = "/llm-analysis/user", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter subscribeToUserLlmAnalysis(Principal principal) {
        String userId = principal != null ? principal.getName() : "anonymous";
        log.info("[LlmAnalysisSseController] 새 SSE 구독 요청 - userId: {}", userId);
        return eventPublisher.addEmitter(userId);
    }

    */
/**
     * SSE 구독자 상태 조회
     *
     * 현재 연결된 SSE 구독자 수를 반환합니다.
     * 모니터링 및 디버깅 목적으로 사용됩니다.
     *
     * @return 구독자 상태 정보
     *//*

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        int subscriberCount = eventPublisher.getSubscriberCount();
        log.debug("[LlmAnalysisSseController] 상태 조회 - 구독자: {}", subscriberCount);

        return ResponseEntity.ok(Map.of(
                "status", "active",
                "subscriberCount", subscriberCount,
                "timestamp", System.currentTimeMillis()
        ));
    }

    */
/**
     * 테스트용 이벤트 발행 (개발/데모용)
     *
     * 수동으로 LLM 분석 이벤트를 발행합니다.
     * TIPS 데모 시연 및 개발 테스트 목적으로 사용됩니다.
     *
     * @param eventType 이벤트 타입
     * @param userId 사용자 ID
     * @param action 보안 결정 (ALLOW, BLOCK, CHALLENGE, ESCALATE)
     * @param riskScore 위험 점수 (0.0-1.0)
     * @param confidence 신뢰도 (0.0-1.0)
     * @return 발행 결과
     *//*

    @PostMapping("/test-event")
    public ResponseEntity<Map<String, Object>> publishTestEvent(
            @RequestParam String eventType,
            @RequestParam(defaultValue = "testUser") String userId,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) Double riskScore,
            @RequestParam(required = false) Double confidence) {

        log.info("[LlmAnalysisSseController] 테스트 이벤트 발행 - type: {}, userId: {}", eventType, userId);

        switch (eventType) {
            case "CONTEXT_COLLECTED":
                eventPublisher.publishContextCollected(userId, "/api/test/resource", "REQUIRED");
                break;
            case "LAYER1_START":
                eventPublisher.publishLayer1Start(userId, "/api/test/resource");
                break;
            case "LAYER1_COMPLETE":
                eventPublisher.publishLayer1Complete(
                        userId,
                        action != null ? action : ZeroTrustAction.ALLOW.name(),
                        riskScore != null ? riskScore : 0.2,
                        confidence != null ? confidence : 0.85,
                        "Test reasoning for Layer1 analysis",
                        "none",
                        500L
                );
                break;
            case "LAYER2_START":
                eventPublisher.publishLayer2Start(userId, "/api/test/resource", "Escalation reason");
                break;
            case "LAYER2_COMPLETE":
                eventPublisher.publishLayer2Complete(
                        userId,
                        action != null ? action : ZeroTrustAction.CHALLENGE.name(),
                        riskScore != null ? riskScore : 0.6,
                        confidence != null ? confidence : 0.75,
                        "Test reasoning for Layer2 analysis",
                        "T1078",
                        1500L
                );
                break;
            case "DECISION_APPLIED":
                eventPublisher.publishDecisionApplied(
                        userId,
                        action != null ? action : ZeroTrustAction.ALLOW.name(),
                        "LAYER1",
                        "/api/test/resource"
                );
                break;
            default:
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "Unknown event type: " + eventType,
                        "validTypes", new String[]{
                                "CONTEXT_COLLECTED", "LAYER1_START", "LAYER1_COMPLETE",
                                "LAYER2_START", "LAYER2_COMPLETE", "DECISION_APPLIED"
                        }
                ));
        }

        return ResponseEntity.ok(Map.of(
                "success", true,
                "eventType", eventType,
                "userId", userId,
                "timestamp", System.currentTimeMillis()
        ));
    }

    */
/**
     * 테스트용 전체 분석 시뮬레이션 (개발/데모용)
     *
     * 전체 LLM 분석 흐름을 시뮬레이션합니다.
     * TIPS 데모 리허설 목적으로 사용됩니다.
     *
     * @param userId 사용자 ID
     * @param escalate Layer2 에스컬레이션 여부
     * @param finalAction 최종 보안 결정
     * @return 시뮬레이션 결과
     *//*

    @PostMapping("/simulate-analysis")
    public ResponseEntity<Map<String, Object>> simulateAnalysis(
            @RequestParam(defaultValue = "demoUser") String userId,
            @RequestParam(defaultValue = "false") boolean escalate,
            @RequestParam(defaultValue = "ALLOW") String finalAction) {

        log.info("[LlmAnalysisSseController] 분석 시뮬레이션 시작 - userId: {}, escalate: {}, finalAction: {}",
                userId, escalate, finalAction);

        String requestPath = "/api/security-test/sensitive/demo-resource";

        // 비동기로 시뮬레이션 실행
        new Thread(() -> {
            try {
                // 1. Context Collected
                eventPublisher.publishContextCollected(userId, requestPath, "REQUIRED");
                Thread.sleep(500);

                // 2. Layer1 Start
                eventPublisher.publishLayer1Start(userId, requestPath);
                Thread.sleep(1000);

                if (escalate) {
                    // 3a. Layer1 Complete (Escalate)
                    eventPublisher.publishLayer1Complete(
                            userId, ZeroTrustAction.ESCALATE.name(), 0.5, 0.35,
                            "Insufficient confidence, escalating to Layer2", "none", 1000L);
                    Thread.sleep(500);

                    // 4. Layer2 Start
                    eventPublisher.publishLayer2Start(userId, requestPath, "Low confidence in Layer1");
                    Thread.sleep(2000);

                    // 5. Layer2 Complete
                    eventPublisher.publishLayer2Complete(
                            userId, finalAction, 0.4, 0.85,
                            "Deep analysis completed by Claude", "T1078", 2000L);
                    Thread.sleep(300);

                    // 6. Decision Applied
                    eventPublisher.publishDecisionApplied(userId, finalAction, "LAYER2", requestPath);

                } else {
                    // 3b. Layer1 Complete (No Escalation)
                    double riskScore = ZeroTrustAction.BLOCK.name().equals(finalAction) ? 0.9 :
                            ZeroTrustAction.CHALLENGE.name().equals(finalAction) ? 0.6 : 0.2;
                    double confidence = 0.85;

                    eventPublisher.publishLayer1Complete(
                            userId, finalAction, riskScore, confidence,
                            "Analysis completed by Llama 8B", "none", 1000L);
                    Thread.sleep(300);

                    // 4. Decision Applied
                    eventPublisher.publishDecisionApplied(userId, finalAction, "LAYER1", requestPath);
                }

                log.info("[LlmAnalysisSseController] 분석 시뮬레이션 완료 - userId: {}", userId);

            } catch (InterruptedException e) {
                log.error("[LlmAnalysisSseController] 시뮬레이션 중단됨", e);
                Thread.currentThread().interrupt();
            }
        }).start();

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Analysis simulation started",
                "userId", userId,
                "escalate", escalate,
                "finalAction", finalAction
        ));
    }
}
*/
