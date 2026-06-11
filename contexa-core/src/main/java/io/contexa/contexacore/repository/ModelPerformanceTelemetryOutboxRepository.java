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

import io.contexa.contexacore.domain.entity.ModelPerformanceTelemetryOutboxRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface ModelPerformanceTelemetryOutboxRepository extends JpaRepository<ModelPerformanceTelemetryOutboxRecord, Long> {

    Optional<ModelPerformanceTelemetryOutboxRecord> findByPeriod(LocalDate period);

    Optional<ModelPerformanceTelemetryOutboxRecord> findTopByOrderByPeriodDesc();

    @Query("""
            select record
            from ModelPerformanceTelemetryOutboxRecord record
            where record.status in :statuses
              and record.period < :today
              and (record.nextAttemptAt is null or record.nextAttemptAt <= :now)
            order by record.period asc
            """)
    List<ModelPerformanceTelemetryOutboxRecord> findDispatchableCompleted(
            @Param("statuses") List<String> statuses,
            @Param("today") LocalDate today,
            @Param("now") LocalDateTime now,
            Pageable pageable);
}
