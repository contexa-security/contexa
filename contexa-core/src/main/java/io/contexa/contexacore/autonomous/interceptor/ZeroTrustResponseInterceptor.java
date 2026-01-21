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

@Component
@Slf4j
public class ZeroTrustResponseInterceptor {

    private final ConcurrentHashMap<String, ResponseContext> activeResponses = new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, Boolean> runtimeInterceptionEnabled = new ConcurrentHashMap<>();

    private static final long CONTEXT_TIMEOUT_MS = 30000;

    public void registerResponse(String requestId, HttpServletResponse response) {
        if (requestId == null || response == null) {
                        return;
        }

        ResponseContext ctx = new ResponseContext();
        ctx.requestId = requestId;
        ctx.responseRef = new WeakReference<>(response);
        ctx.registeredAt = System.currentTimeMillis();
        ctx.committed = false;

        activeResponses.put(requestId, ctx);
            }

    public void unregisterResponse(String requestId) {
        if (requestId != null) {
            activeResponses.remove(requestId);
                    }
    }

    @EventListener
    public void onAnalysisComplete(SecurityAnalysisCompletedEvent event) {
        try {
            String requestId = event.getRequestId();
            String action = event.getAction();
            double riskScore = event.getRiskScore();

            if (!"BLOCK".equalsIgnoreCase(action)) {
                                return;
            }

            if (!isRuntimeInterceptionEnabled(requestId)) {
                                return;
            }

            attemptBlockResponse(requestId, riskScore);

        } catch (Exception e) {
            
            log.error("[ZeroTrust] 분석 완료 이벤트 처리 실패: {}", e.getMessage());
        }
    }

    public void attemptBlockResponse(String requestId, double riskScore) {
        ResponseContext ctx = activeResponses.get(requestId);
        if (ctx == null) {
            
                        return;
        }

        HttpServletResponse response = ctx.responseRef.get();
        if (response == null) {
            
            activeResponses.remove(requestId);
                        return;
        }

        try {
            if (response.isCommitted()) {
                
                log.warn("[ZeroTrust] 차단 불가 - 응답 이미 커밋됨: requestId={}", requestId);
                return;
            }

            response.reset(); 
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
            
                    } catch (IOException e) {
            
                    } catch (Exception e) {
            
            log.error("[ZeroTrust] 차단 시도 중 예상치 못한 오류: {}", e.getMessage());
        }
    }

    @Scheduled(fixedRate = 6000000)
    public void cleanupStaleContexts() {
        long now = System.currentTimeMillis();
        int removedCount = 0;

        var iterator = activeResponses.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            ResponseContext ctx = entry.getValue();

            if (now - ctx.registeredAt > CONTEXT_TIMEOUT_MS || ctx.committed) {
                iterator.remove();
                removedCount++;
            }
        }

        if (removedCount > 0) {
                    }
    }

    public int getActiveContextCount() {
        return activeResponses.size();
    }

    public void enableRuntimeInterception(String requestId) {
        if (requestId != null) {
            runtimeInterceptionEnabled.put(requestId, Boolean.TRUE);
                    }
    }

    public boolean isRuntimeInterceptionEnabled(String requestId) {
        return requestId != null && runtimeInterceptionEnabled.getOrDefault(requestId, false);
    }

    public void clearRuntimeInterception(String requestId) {
        if (requestId != null) {
            runtimeInterceptionEnabled.remove(requestId);
                    }
    }

    private static class ResponseContext {
        String requestId;
        WeakReference<HttpServletResponse> responseRef;
        long registeredAt;
        volatile boolean committed;
    }
}
