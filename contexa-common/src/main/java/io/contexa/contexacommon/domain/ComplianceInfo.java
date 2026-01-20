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