package io.contexa.contexacore.autonomous.interceptor;

import io.contexa.contexacore.autonomous.event.SecurityAnalysisCompletedEvent;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Zero Trust 실시간 응답 차단 인터셉터
 *
 * LLM 분석이 완료되기 전에 요청이 처리되는 경우,
 * 응답이 커밋되기 전에 BLOCK action이 결정되면 강제로 차단한다.
 *
 * 기술적 안정성 원칙:
 * 1. 이미 커밋된 응답은 절대 건드리지 않음
 * 2. 예외 발생 시 graceful degradation (로그만 남김)
 * 3. 스레드 안전성 보장 (WeakReference + null 체크)
 * 4. 타임아웃으로 무한 대기 방지
 *
 * Phase 8: enableRuntimeInterception 플래그 지원
 * - @Protectable(enableRuntimeInterception = true)인 메서드에 대해서만 실시간 차단 시도
 * - ProtectableMethodAuthorizationManager에서 활성화 요청
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Component
@Slf4j
public class ZeroTrustResponseInterceptor {

    /**
     * 활성 응답 컨텍스트 저장소
     */
    private final ConcurrentHashMap<String, ResponseContext> activeResponses = new ConcurrentHashMap<>();

    /**
     * 실시간 응답 차단이 활성화된 요청 ID 저장소
     * @Protectable(enableRuntimeInterception = true)인 메서드 호출 시 활성화됨
     */
    private final ConcurrentHashMap<String, Boolean> runtimeInterceptionEnabled = new ConcurrentHashMap<>();

    /**
     * 컨텍스트 유지 최대 시간 (30초)
     */
    private static final long CONTEXT_TIMEOUT_MS = 30000;

    /**
     * 응답 컨텍스트 등록 (ZeroTrustResponseFilter에서 호출)
     *
     * @param requestId 요청 식별자
     * @param response HttpServletResponse (WeakReference로 보관)
     */
    public void registerResponse(String requestId, HttpServletResponse response) {
        if (requestId == null || response == null) {
            log.debug("[ZeroTrust] 응답 등록 실패 - null 파라미터");
            return;
        }

        ResponseContext ctx = new ResponseContext();
        ctx.requestId = requestId;
        ctx.responseRef = new WeakReference<>(response);
        ctx.registeredAt = System.currentTimeMillis();
        ctx.committed = false;

        activeResponses.put(requestId, ctx);
        log.debug("[ZeroTrust] 응답 등록 완료: requestId={}", requestId);
    }

    /**
     * 응답 컨텍스트 해제 (ZeroTrustResponseFilter에서 호출 - finally 블록)
     *
     * @param requestId 요청 식별자
     */
    public void unregisterResponse(String requestId) {
        if (requestId != null) {
            activeResponses.remove(requestId);
            log.debug("[ZeroTrust] 응답 해제 완료: requestId={}", requestId);
        }
    }

    /**
     * LLM 분석 완료 이벤트 처리
     *
     * 안전한 차단 시도:
     * - enableRuntimeInterception이 활성화된 요청에 대해서만 차단 시도
     * - 이미 커밋된 응답: 차단 불가 (정상 동작 유지)
     * - 아직 커밋 안 된 응답: 403 반환 시도
     * - 예외 발생: 로그만 남기고 정상 흐름 유지
     *
     * @param event 분석 완료 이벤트
     */
    @EventListener
    public void onAnalysisComplete(SecurityAnalysisCompletedEvent event) {
        try {
            String requestId = event.getRequestId();
            String action = event.getAction();
            double riskScore = event.getRiskScore();

            // BLOCK이 아니면 차단 불필요
            if (!"BLOCK".equalsIgnoreCase(action)) {
                log.debug("[ZeroTrust] 차단 불필요 - requestId: {}, action: {}", requestId, action);
                return;
            }

            // enableRuntimeInterception이 활성화된 요청에 대해서만 차단 시도
            if (!isRuntimeInterceptionEnabled(requestId)) {
                log.debug("[ZeroTrust] 실시간 차단 비활성화 - requestId: {}", requestId);
                return;
            }

            attemptBlockResponse(requestId, riskScore);

        } catch (Exception e) {
            // 이벤트 처리 실패 시에도 절대 예외 전파하지 않음
            log.error("[ZeroTrust] 분석 완료 이벤트 처리 실패: {}", e.getMessage());
        }
    }

    /**
     * 응답 차단 시도 (별도 메서드로 직접 호출 가능)
     *
     * @param requestId 요청 식별자
     * @param riskScore 위험도 점수
     */
    public void attemptBlockResponse(String requestId, double riskScore) {
        ResponseContext ctx = activeResponses.get(requestId);
        if (ctx == null) {
            // 이미 응답 완료됨 (정상)
            log.debug("[ZeroTrust] 응답 컨텍스트 없음 (이미 완료): requestId={}", requestId);
            return;
        }

        HttpServletResponse response = ctx.responseRef.get();
        if (response == null) {
            // GC로 수거됨 (정상)
            activeResponses.remove(requestId);
            log.debug("[ZeroTrust] 응답 객체 GC 수거됨: requestId={}", requestId);
            return;
        }

        // 안전한 차단 시도
        try {
            if (response.isCommitted()) {
                // 이미 커밋됨 - 차단 불가 (정상 동작 유지)
                log.warn("[ZeroTrust] 차단 불가 - 응답 이미 커밋됨: requestId={}", requestId);
                return;
            }

            // 차단 가능!
            response.reset(); // 버퍼 초기화
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(String.format(
                "{\"error\":\"ZERO_TRUST_BLOCK\",\"message\":\"Access blocked by security analysis\",\"riskScore\":%.2f,\"requestId\":\"%s\"}",
                riskScore, requestId
            ));
            response.flushBuffer();
            ctx.committed = true;

            log.warn("[ZeroTrust] 실시간 응답 차단 성공: requestId={}, riskScore={}", requestId, riskScore);

        } catch (IllegalStateException e) {
            // getOutputStream() 이미 호출됨 - 정상 흐름 유지
            log.debug("[ZeroTrust] 차단 불가 - 출력 스트림 이미 사용: {}", e.getMessage());
        } catch (IOException e) {
            // I/O 오류 - 정상 흐름 유지
            log.debug("[ZeroTrust] 차단 불가 - I/O 오류: {}", e.getMessage());
        } catch (Exception e) {
            // 기타 예외 - 절대 전파하지 않음
            log.error("[ZeroTrust] 차단 시도 중 예상치 못한 오류: {}", e.getMessage());
        }
    }

    /**
     * 오래된 컨텍스트 정리 (1분마다 실행)
     */
    @Scheduled(fixedRate = 6000000)
    public void cleanupStaleContexts() {
        long now = System.currentTimeMillis();
        int removedCount = 0;

        var iterator = activeResponses.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            ResponseContext ctx = entry.getValue();

            // 타임아웃 초과 또는 이미 커밋된 컨텍스트 제거
            if (now - ctx.registeredAt > CONTEXT_TIMEOUT_MS || ctx.committed) {
                iterator.remove();
                removedCount++;
            }
        }

        if (removedCount > 0) {
            log.debug("[ZeroTrust] 오래된 컨텍스트 {} 개 정리 완료", removedCount);
        }
    }

    /**
     * 활성 컨텍스트 수 조회 (모니터링용)
     *
     * @return 활성 응답 컨텍스트 수
     */
    public int getActiveContextCount() {
        return activeResponses.size();
    }

    // ============================================
    // enableRuntimeInterception 플래그 관리
    // ============================================

    /**
     * 실시간 응답 차단 활성화
     *
     * ProtectableMethodAuthorizationManager에서 @Protectable(enableRuntimeInterception = true)인
     * 메서드 호출 시 이 메서드를 호출하여 활성화
     *
     * @param requestId 요청 ID
     */
    public void enableRuntimeInterception(String requestId) {
        if (requestId != null) {
            runtimeInterceptionEnabled.put(requestId, Boolean.TRUE);
            log.debug("[ZeroTrust] 실시간 응답 차단 활성화: requestId={}", requestId);
        }
    }

    /**
     * 실시간 응답 차단 활성화 여부 확인
     *
     * @param requestId 요청 ID
     * @return 활성화 여부
     */
    public boolean isRuntimeInterceptionEnabled(String requestId) {
        return requestId != null && runtimeInterceptionEnabled.getOrDefault(requestId, false);
    }

    /**
     * 실시간 응답 차단 플래그 해제
     *
     * ZeroTrustResponseFilter의 finally 블록에서 호출하여 메모리 누수 방지
     *
     * @param requestId 요청 ID
     */
    public void clearRuntimeInterception(String requestId) {
        if (requestId != null) {
            runtimeInterceptionEnabled.remove(requestId);
            log.debug("[ZeroTrust] 실시간 응답 차단 플래그 해제: requestId={}", requestId);
        }
    }

    /**
     * 응답 컨텍스트 내부 클래스
     */
    private static class ResponseContext {
        String requestId;
        WeakReference<HttpServletResponse> responseRef;
        long registeredAt;
        volatile boolean committed;
    }
}
