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
package io.contexa.contexaiam.common.event.dto;

import java.util.Set;

public class PolicyChangedEvent extends DomainEvent {
    private final Long policyId;
    private final Set<Long> permissionIds; 

    public PolicyChangedEvent(Long policyId, Set<Long> permissionIds) { 
        this.policyId = policyId;
        this.permissionIds = permissionIds;
    }

    public Long getPolicyId() { return policyId; }
    public Set<Long> getPermissionIds() { return permissionIds; } 
}
