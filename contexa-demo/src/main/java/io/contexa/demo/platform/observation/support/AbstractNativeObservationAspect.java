package io.contexa.demo.platform.observation.support;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.function.Supplier;

public abstract class AbstractNativeObservationAspect {

    private final Logger log = LoggerFactory.getLogger(getClass());

    protected <T> T readSafely(Supplier<T> source) {
        try {
            return source.get();
        } catch (RuntimeException unavailable) {
            log.warn("Native observation unavailable: {}", unavailable.getClass().getSimpleName());
            return null;
        }
    }

    protected void observeSafely(Runnable operation) {
        readSafely(() -> {
            operation.run();
            return Boolean.TRUE;
        });
    }
}
