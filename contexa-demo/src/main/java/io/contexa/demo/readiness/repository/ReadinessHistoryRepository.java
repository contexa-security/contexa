package io.contexa.demo.readiness.repository;

import io.contexa.demo.readiness.dto.ReadinessReport;
import io.contexa.demo.readiness.dto.StoredReadiness;

import java.util.List;
import java.util.UUID;

public interface ReadinessHistoryRepository {

    UUID save(ReadinessReport report);

    List<StoredReadiness> history();
}
