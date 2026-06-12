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

import io.contexa.contexacore.domain.entity.SoarApprovalRequest;
import jakarta.persistence.LockModeType;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface SoarApprovalRequestRepository extends JpaRepository<SoarApprovalRequest, Long> {

    List<SoarApprovalRequest> findByStatusOrderByCreatedAtDesc(String status);

    List<SoarApprovalRequest> findTop10ByStatusOrderByCreatedAtDesc(String status);

    long countByStatus(String status);

    @Deprecated
    List<SoarApprovalRequest> findByReviewerIdAndStatus(String reviewerId, String status);

    List<SoarApprovalRequest> findByApprovedByAndStatus(String approvedBy, String status);

    @Deprecated
    List<SoarApprovalRequest> findByPlaybookInstanceId(String playbookInstanceId);

    List<SoarApprovalRequest> findByIncidentId(String incidentId);

    List<SoarApprovalRequest> findByIncidentIdIn(Collection<String> incidentIds);

    SoarApprovalRequest findByRequestId(String requestId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select request from SoarApprovalRequest request where request.requestId = :requestId")
    Optional<SoarApprovalRequest> findForUpdateByRequestId(@Param("requestId") String requestId);

    List<SoarApprovalRequest> findBySessionId(String sessionId);

    List<SoarApprovalRequest> findByRiskLevelOrderByCreatedAtDesc(String riskLevel);

    List<SoarApprovalRequest> findByRequestIdIn(Collection<String> requestIds);

    List<SoarApprovalRequest> findByCreatedAtBetweenOrderByCreatedAtDesc(LocalDateTime startDate, LocalDateTime endDate);

    List<SoarApprovalRequest> findTop20ByToolNameOrderByCreatedAtDesc(String toolName);

    @Query("""
            select request
            from SoarApprovalRequest request
            where (:statusesEmpty = true or upper(request.status) in :statuses)
              and (:riskLevel is null or upper(request.riskLevel) = :riskLevel)
              and (:toolName is null or lower(request.toolName) like :toolName)
              and (:incidentId is null or upper(request.incidentId) = :incidentId)
              and (:organizationId is null or upper(request.organizationId) = :organizationId)
              and (:requestedBy is null or lower(request.requestedBy) like :requestedBy)
            order by request.createdAt desc
            """)
    Page<SoarApprovalRequest> searchOperations(
            @Param("statuses") Collection<String> statuses,
            @Param("statusesEmpty") boolean statusesEmpty,
            @Param("riskLevel") String riskLevel,
            @Param("toolName") String toolName,
            @Param("incidentId") String incidentId,
            @Param("organizationId") String organizationId,
            @Param("requestedBy") String requestedBy,
            Pageable pageable);
}

