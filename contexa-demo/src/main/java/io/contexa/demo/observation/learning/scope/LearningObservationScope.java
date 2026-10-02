package io.contexa.demo.observation.learning.scope;

import io.contexa.demo.observation.learning.dto.LearningSource;

public final class LearningObservationScope {

    private static final ThreadLocal<LearningSource> CURRENT = new ThreadLocal<>();

    private LearningObservationScope() {
    }

    public static LearningSource current() {
        return CURRENT.get();
    }

    public static void restore(LearningSource source) {
        if (source == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(source);
        }
    }
}
