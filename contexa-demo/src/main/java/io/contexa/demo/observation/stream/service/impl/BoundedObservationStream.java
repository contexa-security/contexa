package io.contexa.demo.observation.stream.service.impl;

import io.contexa.demo.observation.request.service.WorkspaceEvidenceQuery;
import io.contexa.demo.observation.stream.dto.ObservationNotice;
import io.contexa.demo.observation.stream.repository.ObservationFeedRepository;
import io.contexa.demo.observation.stream.service.ObservationStream;
import io.contexa.demo.observation.stream.service.support.ObservationConnection;
import io.contexa.demo.workspace.evidence.service.WorkspaceEvidenceScope;
import jakarta.annotation.PreDestroy;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class BoundedObservationStream implements ObservationStream {

    private final WorkspaceEvidenceQuery evidence;
    private final Map<String, ObservationFeedRepository> arms;
    private final WorkspaceEvidenceScope scope;
    private final Map<UUID, ObservationConnection> connections = new ConcurrentHashMap<>();
    private final ThreadPoolExecutor workers = new ThreadPoolExecutor(0, 8, 30, TimeUnit.SECONDS,
            new SynchronousQueue<>(), task -> {
                Thread thread = new Thread(task, "lab-observation-stream");
                thread.setDaemon(true);
                return thread;
            });

    public BoundedObservationStream(WorkspaceEvidenceQuery evidence, Map<String, ObservationFeedRepository> arms,
            WorkspaceEvidenceScope scope) {
        this.evidence = evidence;
        this.arms = Map.copyOf(arms);
        this.scope = scope;
    }

    @Override
    public synchronized SseEmitter open(String arm, UUID requestId, UUID visitorId,
            Instant visitorExpiresAt, long after) {
        if (after < 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_OBSERVATION_CURSOR");
        }
        ObservationFeedRepository feed = arms.get(arm);
        if (feed == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        evidence.find(arm, requestId, visitorId);
        scope.withOwner(visitorId, () -> {
            feed.checkCursor(requestId, visitorId, after);
            return null;
        });
        if (!visitorExpiresAt.isAfter(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        long ownerConnections = connections.values().stream()
                .filter(connection -> connection.visitorId().equals(visitorId)).count();
        if (connections.size() >= 8 || ownerConnections >= 2) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "OBSERVATION_STREAM_LIMIT");
        }
        UUID connectionId = UUID.randomUUID();
        ObservationConnection connection = new ObservationConnection(visitorId);
        connections.put(connectionId, connection);
        try {
            workers.execute(() -> send(connectionId, connection, feed, requestId, visitorExpiresAt, after));
        } catch (RejectedExecutionException unavailable) {
            connections.remove(connectionId);
            connection.close();
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "OBSERVATION_STREAM_LIMIT");
        }
        return connection.emitter();
    }

    private void send(UUID connectionId, ObservationConnection connection, ObservationFeedRepository feed,
            UUID requestId, Instant visitorExpiresAt, long after) {
        long cursor = after;
        Instant deadline = Instant.now().plusSeconds(20);
        int idle = 0;
        try {
            connection.emitter().send(SseEmitter.event().name("connected").reconnectTime(2000)
                    .data(Map.of("requestId", requestId, "after", Long.toString(cursor))));
            while (!connection.closed() && Instant.now().isBefore(deadline)
                    && Instant.now().isBefore(visitorExpiresAt)) {
                long previous = cursor;
                List<ObservationNotice> notices = scope.withOwner(connection.visitorId(),
                        () -> feed.read(requestId, connection.visitorId(), previous));
                for (ObservationNotice notice : notices) {
                    if (connection.closed()) {
                        break;
                    }
                    connection.emitter().send(SseEmitter.event().name("observation")
                            .id(Long.toString(notice.sequence())).data(notice));
                    cursor = notice.sequence();
                }
                if (++idle % 5 == 0) {
                    connection.emitter().send(SseEmitter.event().name("refresh")
                            .data(Map.of("observedAt", Instant.now().toString())));
                }
                Thread.sleep(1000);
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (IOException | RuntimeException unavailable) {
            // A failed or slow subscriber cannot call or modify the native security pipeline.
        } finally {
            connection.close();
            connections.remove(connectionId);
        }
    }

    @PreDestroy
    public void close() {
        connections.values().forEach(ObservationConnection::close);
        workers.shutdownNow();
    }
}
