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
package io.contexa.contexacore.autonomous.context.collector;

import lombok.Builder;
import lombok.Value;

import java.util.List;
import io.contexa.contexacore.autonomous.context.collector.ContextSnapshot;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;

@Value
@Builder
public class ProtectableWorkProfileSnapshot implements ContextSnapshot {
    String tenantId;
    String userId;
    Integer observationCount;
    Integer windowDays;
    List<String> frequentProtectableResources;
    List<String> frequentActionFamilies;
    List<Integer> normalAccessHours;
    List<Integer> normalAccessDays;
    Double normalRequestRate;
    Double protectableInvocationDensity;
    List<String> protectableResourceHeatmap;
    List<String> frequentSensitiveResourceCategories;
    String normalReadWriteExportRatio;
    String summary;
    ContextTrustProfile trustProfile;
}
