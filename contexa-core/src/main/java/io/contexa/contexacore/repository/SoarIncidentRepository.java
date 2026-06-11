/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
