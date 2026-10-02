package io.contexa.demo.observation.shared;

import io.contexa.demo.observation.health.service.CollectorMeter;
import io.contexa.demo.observation.health.service.CollectorRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public abstract class AbstractBufferedObservationSink<T> {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final BlockingQueue<T> pending;
    private final CollectorMeter meter;
    private volatile boolean running;
    private Thread worker;

    protected AbstractBufferedObservationSink(CollectorRegistry collectors, String source) {
        this(collectors, source, 512);
    }

    protected AbstractBufferedObservationSink(CollectorRegistry collectors, String source, int capacity) {
        pending = new ArrayBlockingQueue<>(capacity);
        meter = collectors.register(source);
    }

    @PostConstruct
    public void start() {
        running = true;
        worker = new Thread(this::drain, getClass().getSimpleName());
        worker.setDaemon(true);
        worker.start();
    }

    public void offer(T observation) {
        synchronized (meter) {
            meter.offered(running && pending.offer(observation));
        }
    }

    public long missingCount() {
        return meter.missingCount();
    }

    protected abstract void persist(T observation);

    private void drain() {
        while (running) {
            T observation;
            try {
                observation = pending.take();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
            meter.beginWrite();
            boolean confirmed = false;
            try {
                persist(observation);
                confirmed = true;
            } catch (RuntimeException unavailable) {
                log.warn("Observation storage unconfirmed: {}", unavailable.getClass().getSimpleName());
            } finally {
                meter.finishWrite(confirmed);
            }
        }
    }

    @PreDestroy
    public void close() {
        List<T> abandoned = new ArrayList<>();
        synchronized (meter) {
            running = false;
            pending.drainTo(abandoned);
            meter.abandon(abandoned.size());
        }
        if (worker != null) {
            worker.interrupt();
            try {
                worker.join(5500);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
        meter.stopped(worker != null && worker.isAlive());
        if (!abandoned.isEmpty()) {
            log.warn("Observation queue closed with {} unpersisted items", abandoned.size());
        }
    }
}
