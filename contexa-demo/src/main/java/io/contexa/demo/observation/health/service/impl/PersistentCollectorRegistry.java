package io.contexa.demo.observation.health.service.impl;

import io.contexa.demo.observation.health.dto.CollectorSnapshot;
import io.contexa.demo.observation.health.repository.CollectorStatusRepository;
import io.contexa.demo.observation.health.service.CollectorMeter;
import io.contexa.demo.observation.health.service.CollectorRegistry;
import io.contexa.demo.observation.health.service.support.MutableCollectorMeter;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
@Profile({"baseline", "contexa"})
public class PersistentCollectorRegistry implements CollectorRegistry {

    private static final Logger log = LoggerFactory.getLogger(PersistentCollectorRegistry.class);
    private static final List<String> SOURCES = List.of("HTTP", "ENGINE", "MODEL", "PROVIDER");
    private final UUID instanceId = UUID.randomUUID();
    private final Instant startedAt = Instant.now();
    private final Map<String, CollectorMeter> meters = new ConcurrentHashMap<>();
    private final CollectorStatusRepository statuses;
    private final ScheduledExecutorService writer = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "lab-collector-status");
        thread.setDaemon(true);
        return thread;
    });

    public PersistentCollectorRegistry(CollectorStatusRepository statuses) {
        this.statuses = statuses;
    }

    @Override
    public UUID instanceId() {
        return instanceId;
    }

    @Override
    public CollectorMeter register(String source) {
        if (!SOURCES.contains(source)) {
            throw new IllegalArgumentException("Unknown observation source");
        }
        return meters.computeIfAbsent(source, name -> new MutableCollectorMeter(instanceId, name, startedAt));
    }

    @PostConstruct
    public void start() {
        writer.scheduleWithFixedDelay(this::flush, 2, 2, TimeUnit.SECONDS);
    }

    private void flush() {
        List<CollectorSnapshot> snapshots = meters.values().stream().map(CollectorMeter::snapshot).toList();
        if (snapshots.isEmpty()) {
            return;
        }
        try {
            statuses.save(snapshots);
        } catch (RuntimeException unavailable) {
            log.warn("Collector status could not be saved: {}", unavailable.getClass().getSimpleName());
        }
    }

    @PreDestroy
    public void close() {
        writer.shutdown();
        try {
            if (writer.awaitTermination(6, TimeUnit.SECONDS)) {
                flush();
            } else {
                writer.shutdownNow();
            }
        } catch (InterruptedException interrupted) {
            writer.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
