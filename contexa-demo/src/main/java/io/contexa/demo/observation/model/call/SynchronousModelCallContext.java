package io.contexa.demo.observation.model.call;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** Scoped only to the actual synchronous advisor chain; never propagated by inference. */
@Component
@Profile("contexa")
public class SynchronousModelCallContext implements ModelCallContext {

    private final ThreadLocal<ModelCallReference> active = new ThreadLocal<>();

    @Override
    public ModelCallScope open(ModelCallReference reference) {
        ModelCallReference previous = active.get();
        active.set(reference);
        return () -> {
            if (previous == null) {
                active.remove();
            } else {
                active.set(previous);
            }
        };
    }

    @Override
    public ModelCallReference current() {
        return active.get();
    }
}
