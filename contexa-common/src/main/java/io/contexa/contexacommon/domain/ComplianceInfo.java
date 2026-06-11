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
package io.contexa.contexacommon.domain;

import lombok.Getter;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


@Getter
public class ComplianceInfo {
    private final Map<String, Boolean> complianceChecks;
    private String overallStatus;
    private String complianceFramework;
    
    public ComplianceInfo() {
        this.complianceChecks = new ConcurrentHashMap<>();
        this.overallStatus = "PENDING";
    }
    
    public void addComplianceCheck(String checkName, boolean passed) {
        complianceChecks.put(checkName, passed);
        updateOverallStatus();
    }
    
    private void updateOverallStatus() {
        if (complianceChecks.isEmpty()) {
            this.overallStatus = "PENDING";
        } else if (complianceChecks.values().stream().allMatch(Boolean::booleanValue)) {
            this.overallStatus = "COMPLIANT";
        } else {
            this.overallStatus = "NON_COMPLIANT";
        }
    }
    
    public void setComplianceFramework(String complianceFramework) {
        this.complianceFramework = complianceFramework;
    }

    @Override
    public String toString() {
        return String.format("ComplianceInfo{status='%s', framework='%s', checks=%d}", 
                overallStatus, complianceFramework, complianceChecks.size());
    }
} 