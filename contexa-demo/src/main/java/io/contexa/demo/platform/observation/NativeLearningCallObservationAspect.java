package io.contexa.demo.platform.observation;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.demo.observation.learning.dto.LearningSource;
import io.contexa.demo.observation.learning.scope.LearningObservationScope;
import io.contexa.demo.observation.learning.service.LearningObservationRecorder;
import io.contexa.demo.platform.observation.support.AbstractNativeDecisionObservationAspect;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Aspect
@Component
@Profile("contexa")
public class NativeLearningCallObservationAspect extends AbstractNativeDecisionObservationAspect {

    private final LearningObservationRecorder recorder;

    public NativeLearningCallObservationAspect(LearningObservationRecorder recorder) {
        this.recorder = recorder;
    }

    @Around("execution(* io.contexa.contexacore.autonomous.baseline.BaselineLearningService.learnIfNormal(..))"
            + " && args(username, decision, event)")
    public Object observe(ProceedingJoinPoint invocation, String username, SecurityDecision decision, SecurityEvent event)
            throws Throwable {
        LearningSource previous = LearningObservationScope.current();
        LearningSource source = readSafely(() -> source(username, decision, event));
        LearningObservationScope.restore(source);
        try {
            Object returned = invocation.proceed();
            observeSafely(() -> recorder.callReturned(source, returned instanceof Boolean value ? value : null, null));
            return returned;
        } catch (Throwable failure) {
            observeSafely(() -> recorder.callReturned(source, null, failure.getClass().getSimpleName()));
            throw failure;
        } finally {
            LearningObservationScope.restore(previous);
        }
    }
}
