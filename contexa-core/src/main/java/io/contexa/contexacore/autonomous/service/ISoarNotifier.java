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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.autonomous.domain.NotificationResult;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

public interface ISoarNotifier {

    CompletableFuture<NotificationResult> notifyCriticalSituation(SoarContext context);

    CompletableFuture<NotificationResult> notifyHighRiskTool(String toolName, Map<String, Object> toolParameters, SoarContext context);

    Map<String, Object> getNotificationStatistics();

    default NotificationResult notifyCriticalEvent(Object event, Map<String, Object> data) {
        
        return NotificationResult.success("default-notification", "Default notification");
    }

    default NotificationResult notifyWarningEvent(Object event, Map<String, Object> data) {
        
        return NotificationResult.success("default-notification", "Default notification");
    }

    default NotificationResult notifyApprovalRequired(Object event, Map<String, Object> data) {
        
        return NotificationResult.success("default-notification", "Default notification");
    }

    default NotificationResult notifyEscalation(Object event, Map<String, Object> data) {
        
        return NotificationResult.success("default-notification", "Default notification");
    }

    boolean isSoarAvailable();
    
}