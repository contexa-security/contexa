package io.contexa.demo.observation.stream.repository;

import io.contexa.demo.observation.stream.dto.ObservationNotice;

import java.util.List;
import java.util.UUID;

public interface ObservationFeedRepository {

    void checkCursor(UUID requestId, UUID visitorId, long after);

    List<ObservationNotice> read(UUID requestId, UUID visitorId, long after);
}
