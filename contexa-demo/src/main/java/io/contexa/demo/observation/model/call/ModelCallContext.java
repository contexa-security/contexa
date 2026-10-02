package io.contexa.demo.observation.model.call;

public interface ModelCallContext {

    ModelCallScope open(ModelCallReference reference);

    ModelCallReference current();
}
