package io.contexa.demo.platform.observation;

import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.demo.observation.learning.dto.BaselineValueSnapshot;
import io.contexa.demo.observation.learning.dto.LearningSource;
import io.contexa.demo.observation.learning.scope.LearningObservationScope;
import io.contexa.demo.observation.learning.service.BaselineSnapshotQuery;
import io.contexa.demo.observation.learning.service.LearningObservationRecorder;
import io.contexa.demo.platform.observation.support.AbstractNativeObservationAspect;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.Objects;

@Aspect
@Component
@Profile("contexa")
public class NativeBaselineWriteObservationAspect extends AbstractNativeObservationAspect {

    private final ObjectProvider<BaselineSnapshotQuery> snapshots;
    private final LearningObservationRecorder recorder;

    public NativeBaselineWriteObservationAspect(ObjectProvider<BaselineSnapshotQuery> snapshots,
            LearningObservationRecorder recorder) {
        this.snapshots = snapshots;
        this.recorder = recorder;
    }

    @Around("execution(* io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore+.saveUserBaseline(..))"
            + " && args(username, value)")
    public Object observe(ProceedingJoinPoint invocation, String username, BaselineVector value) throws Throwable {
        LearningSource source = LearningObservationScope.current();
        if (source == null || !Objects.equals(source.username(), username)) {
            return invocation.proceed();
        }
        BaselineValueSnapshot submitted = readSafely(() -> snapshots.getObject().capture(value));
        Object returned;
        try {
            returned = invocation.proceed();
        } catch (Throwable failure) {
            observeSafely(() -> recorder.writeReturned(source, submitted, null, failure.getClass().getSimpleName()));
            throw failure;
        }
        BaselineValueSnapshot observed = readSafely(() -> snapshots.getObject().read(username));
        observeSafely(() -> recorder.writeReturned(source, submitted, observed, null));
        return returned;
    }
}
