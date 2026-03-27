package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.SoarIncidentStatus;
import io.contexa.contexacore.domain.entity.SoarIncident;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SoarIncidentRepository extends JpaRepository<SoarIncident, UUID> {
    List<SoarIncident> findByStatusInOrderByUpdatedAtDesc(List<SoarIncidentStatus> statuses);

    List<SoarIncident> findTop10ByStatusInOrderByUpdatedAtDesc(List<SoarIncidentStatus> statuses);

    long countByStatusIn(List<SoarIncidentStatus> statuses);

    Optional<SoarIncident> findByIncidentId(String incidentId);

    @Query("""
            select incident
            from SoarIncident incident
            where (:statusesEmpty = true or incident.status in :statuses)
              and (:severity is null or upper(incident.severity) = :severity)
              and (:type is null or lower(incident.type) like :type)
            order by incident.updatedAt desc
            """)
    Page<SoarIncident> searchOperations(
            @Param("statuses") Collection<SoarIncidentStatus> statuses,
            @Param("statusesEmpty") boolean statusesEmpty,
            @Param("severity") String severity,
            @Param("type") String type,
            Pageable pageable);
}
