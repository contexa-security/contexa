package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.domain.SoarIncidentStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface SoarIncidentRepository extends JpaRepository<SoarIncident, UUID> {
    List<SoarIncident> findByStatusInOrderByUpdatedAtDesc(List<SoarIncidentStatus> statuses);
}
