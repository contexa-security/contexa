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

import io.contexa.contexacore.domain.entity.SoarApprovalVote;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface SoarApprovalVoteRepository extends JpaRepository<SoarApprovalVote, Long> {

    List<SoarApprovalVote> findByRequestIdOrderByCreatedAtAsc(String requestId);

    List<SoarApprovalVote> findByRequestIdInOrderByCreatedAtAsc(Collection<String> requestIds);

    List<SoarApprovalVote> findByRequestIdAndStepNumberOrderByCreatedAtAsc(String requestId, Integer stepNumber);

    Optional<SoarApprovalVote> findByRequestIdAndApproverIdAndStepNumber(String requestId, String approverId, Integer stepNumber);

    boolean existsByRequestIdAndApproverIdAndStepNumber(String requestId, String approverId, Integer stepNumber);

    void deleteByRequestId(String requestId);
}
