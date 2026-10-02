package io.contexa.demo.observation.stream.service.support;

import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

public class ObservationConnection {

    private final UUID visitorId;
    private final SseEmitter emitter = new SseEmitter(25000L);
    private final AtomicBoolean closed = new AtomicBoolean();

    public ObservationConnection(UUID visitorId) {
        this.visitorId = visitorId;
        emitter.onCompletion(() -> closed.set(true));
        emitter.onTimeout(this::close);
        emitter.onError(error -> closed.set(true));
    }

    public UUID visitorId() {
        return visitorId;
    }

    public SseEmitter emitter() {
        return emitter;
    }

    public boolean closed() {
        return closed.get();
    }

    public void close() {
        if (closed.compareAndSet(false, true)) {
            emitter.complete();
        }
    }
}
