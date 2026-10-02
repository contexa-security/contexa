package io.contexa.demo.platform.observation;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.llm.observation.LlmObservationContext;
import io.contexa.contexacore.std.pipeline.observation.SecurityDecisionObservationContextResolver;
import io.contexa.demo.observation.pipeline.service.PipelineObservationRecorder;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/** Observes the native terminal signal without consuming, retrying, or replacing its value. */
@Aspect
@Component
@Profile("contexa")
public class NativeModelStepObservationAspect {

    private static final Logger log = LoggerFactory.getLogger(NativeModelStepObservationAspect.class);
    private final PipelineObservationRecorder recorder;

    public NativeModelStepObservationAspect(PipelineObservationRecorder recorder) {
        this.recorder = recorder;
    }

    @Around("execution(* io.contexa.contexacore.std.pipeline.step.LLMExecutionStep.execute(..)) && args(request, context)")
    public Object observe(ProceedingJoinPoint invocation, AIRequest<?> request, PipelineExecutionContext context)
            throws Throwable {
        LlmObservationContext source = source(request);
        Object original;
        try {
            original = invocation.proceed();
        } catch (Throwable failure) {
            record(source, context, "ERROR", failure.getClass().getSimpleName());
            throw failure;
        }
        if (!(original instanceof Mono<?> result)) {
            return original;
        }
        return result.doOnSuccess(value -> record(source, context, value == null ? "EMPTY" : "COMPLETED", null))
                .doOnError(failure -> record(source, context, "ERROR", failure.getClass().getSimpleName()))
                .doOnCancel(() -> record(source, context, "CANCELLED", null));
    }

    private LlmObservationContext source(AIRequest<?> request) {
        try {
            return SecurityDecisionObservationContextResolver.resolve(request);
        } catch (RuntimeException unavailable) {
            log.warn("Model step source missing: {}", unavailable.getClass().getSimpleName());
            return null;
        }
    }

    private void record(LlmObservationContext source, PipelineExecutionContext context, String completion, String failureType) {
        try {
            recorder.record(source, context, completion, failureType);
        } catch (RuntimeException unavailable) {
            log.warn("Model step observation missing: {}", unavailable.getClass().getSimpleName());
        }
    }
}
