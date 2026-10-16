package io.contexa.demo.platform.observation;

import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
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
        if (source == null || !ownedBy(username, source.username())) {
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

    /** A personal baseline key is the user alone or the user within a tenant ({@code tenant::user}, W5-10 D9). */
    private static boolean ownedBy(String key, String username) {
        return key != null && username != null
                && (key.equals(username) || key.endsWith(BaselineDataStore.TENANT_SEPARATOR + username));
    }
}
