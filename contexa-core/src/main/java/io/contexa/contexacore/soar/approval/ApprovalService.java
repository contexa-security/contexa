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
package io.contexa.contexacore.soar.approval;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.SoarContext;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public interface ApprovalService {

    String requestApproval(SoarContext soarContext, ApprovalRequestDetails requestDetails);

    ApprovalRequest.ApprovalStatus getApprovalStatus(String approvalId);

    void handleApprovalResponse(String approvalId, boolean isApproved, String comment, String reviewer);

    default void handleApprovalResponse(
            String approvalId,
            boolean isApproved,
            String comment,
            String reviewer,
            Set<String> reviewerRoles) {
        handleApprovalResponse(approvalId, isApproved, comment, reviewer);
    }

    Set<String> getPendingApprovalIds();

    int getPendingCount();

    default CompletableFuture<Boolean> requestApproval(ApprovalRequest request) {
        throw new UnsupportedOperationException("requestApproval(ApprovalRequest) not implemented");
    }

    default void processApprovalResponse(String requestId, boolean approved, String reviewer, String comment) {
        handleApprovalResponse(requestId, approved, comment, reviewer);
    }

    default void processApprovalResponse(
            String requestId,
            boolean approved,
            String reviewer,
            String comment,
            Set<String> reviewerRoles) {
        handleApprovalResponse(requestId, approved, comment, reviewer, reviewerRoles);
    }

    default boolean waitForApprovalSync(ApprovalRequest request) {
        throw new UnsupportedOperationException("waitForApprovalSync not implemented");
    }

    default ApprovalRequest saveApprovalRequest(ApprovalRequest request) {
        throw new UnsupportedOperationException("saveApprovalRequest not implemented");
    }

    default void sendApprovalNotification(ApprovalRequest request) {
        throw new UnsupportedOperationException("sendApprovalNotification not implemented");
    }

    default void processApproval(String approvalId, boolean approved, String reason) {
        handleApprovalResponse(approvalId, approved, reason, "system");
    }

    default List<ApprovalRequest> getPendingApprovals() {
        return List.of();
    }

    default void submitApprovalRequest(ApprovalRequest request) {
        saveApprovalRequest(request);
        sendApprovalNotification(request);
    }

    default void approve(String approvalId) {
        handleApprovalResponse(approvalId, true, "Approved", "system");
    }

    default void reject(String approvalId) {
        handleApprovalResponse(approvalId, false, "Rejected", "system");
    }

    default void cancelApproval(String approvalId, String reason) {
        throw new UnsupportedOperationException("cancelApproval not implemented");
    }

    default void reassignApproval(String approvalId, String assigneeId, String assigneeRole, String requestedBy, String reason) {
        throw new UnsupportedOperationException("reassignApproval not implemented");
    }

    default String reopenApproval(String approvalId, String requestedBy, String reason) {
        throw new UnsupportedOperationException("reopenApproval not implemented");
    }

    default void bulkHandleApprovals(
            List<String> approvalIds,
            boolean approved,
            String comment,
            String reviewer,
            Set<String> reviewerRoles) {
        throw new UnsupportedOperationException("bulkHandleApprovals not implemented");
    }

    default ApprovalRequest getApprovalRequest(String approvalId) {
        return null;
    }
}
