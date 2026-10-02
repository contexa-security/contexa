package io.contexa.demo.observation.stream.service;

import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Instant;
import java.util.UUID;

public interface ObservationStream {

    SseEmitter open(String arm, UUID requestId, UUID visitorId, Instant visitorExpiresAt, long after);
}
