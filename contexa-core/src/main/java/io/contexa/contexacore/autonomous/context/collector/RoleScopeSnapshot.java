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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import io.contexa.contexacore.autonomous.context.collector.ContextSnapshot;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleScopeSnapshot implements ContextSnapshot {

    private String summary;

    private String currentResourceFamily;

    private String currentActionFamily;

    @Builder.Default
    private List<String> expectedResourceFamilies = new ArrayList<>();

    @Builder.Default
    private List<String> expectedActionFamilies = new ArrayList<>();

    @Builder.Default
    private List<String> forbiddenResourceFamilies = new ArrayList<>();

    @Builder.Default
    private List<String> forbiddenActionFamilies = new ArrayList<>();

    @Builder.Default
    private List<String> normalApprovalPatterns = new ArrayList<>();

    @Builder.Default
    private List<String> normalEscalationPatterns = new ArrayList<>();

    @Builder.Default
    private List<String> recentPermissionChanges = new ArrayList<>();

    private Boolean resourceFamilyDrift;

    private Boolean actionFamilyDrift;

    private Boolean temporaryElevation;

    private String temporaryElevationReason;

    private Boolean elevatedPrivilegeWindowActive;

    private String elevationWindowSummary;

    private ContextTrustProfile trustProfile;
}
