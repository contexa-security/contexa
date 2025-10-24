package io.contexa.contexaiam.admin.web.workflow.orchestrator.dto;

import io.contexa.contexaiam.admin.web.studio.dto.InitiateGrantRequestDto;
import java.util.List; // [신규] import

public class WorkflowRequest {
    private InitiateGrantRequestDto initialRequest;
    private String policyName;
    private String policyDescription;
    private List<Long> selectedRoleIds; // [신규] 권한을 할당할 역할 ID 목록

    // Getters and Setters
    public InitiateGrantRequestDto getInitialRequest() { return initialRequest; }
    public void setInitialRequest(InitiateGrantRequestDto initialRequest) { this.initialRequest = initialRequest; }
    public String getPolicyName() { return policyName; }
    public void setPolicyName(String policyName) { this.policyName = policyName; }
    public String getPolicyDescription() { return policyDescription; }
    public void setPolicyDescription(String policyDescription) { this.policyDescription = policyDescription; }
    public List<Long> getSelectedRoleIds() { return selectedRoleIds; } // [신규] Getter and Setter
    public void setSelectedRoleIds(List<Long> selectedRoleIds) { this.selectedRoleIds = selectedRoleIds; }
}