package io.contexa.demo.observation.model.call;

public interface ModelCallScope extends AutoCloseable {

    @Override
    void close();
}
