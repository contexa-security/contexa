package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

/**
 * sandbox 전용 Layer1 실행 context aspect.
 *
 * 목적:
 * - 실제 Layer1 analyzeWithContext 실행 thread와 현재 event/requestId를 thread-local로 연결
 * - 그 안에서 발생하는 vector store / similarity search / prompt authorization 관측값을
 *   동일한 event 기준으로 묶기 위함
 */
@Aspect
public class SandboxLayer1ExecutionAspect {

    private final SandboxRetrievalAuditStore sandboxRetrievalAuditStore;

    public SandboxLayer1ExecutionAspect(SandboxRetrievalAuditStore sandboxRetrievalAuditStore) {
        this.sandboxRetrievalAuditStore = sandboxRetrievalAuditStore;
    }

    @Around("execution(* io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy.evaluate(..)) && args(event)")
    public Object bindCurrentEvent(ProceedingJoinPoint proceedingJoinPoint, SecurityEvent event) throws Throwable {
        sandboxRetrievalAuditStore.begin(event);
        try {
            return proceedingJoinPoint.proceed();
        } finally {
            sandboxRetrievalAuditStore.end();
        }
    }
}
