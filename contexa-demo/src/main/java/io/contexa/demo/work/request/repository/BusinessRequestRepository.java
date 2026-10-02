package io.contexa.demo.work.request.repository;

import io.contexa.demo.work.request.dto.WorkRequestSnapshot;

import java.util.Optional;
import java.util.UUID;

public interface BusinessRequestRepository {

    void append(WorkRequestSnapshot snapshot);

    Optional<WorkRequestSnapshot> find(UUID requestId);
}
