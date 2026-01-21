package io.contexa.contexaiam.admin.web.workflow.orchestrator.dto;

import io.contexa.contexaiam.admin.web.studio.dto.InitiateGrantRequestDto;
import java.util.List; 

public class WorkflowRequest {
    private InitiateGrantRequestDto initialRequest;
    private String policyName;
    private String policyDescription;
    private List<Long> selectedRoleIds; 

    public InitiateGrantRequestDto getInitialRequest() { return initialRequest; }
    public void setInitialRequest(InitiateGrantRequestDto initialRequest) { this.initialRequest = initialRequest; }
    public String getPolicyName() { return policyName; }
    public void setPolicyName(String policyName) { this.policyName = policyName; }
    public String getPolicyDescription() { return policyDescription; }
    public void setPolicyDescription(String policyDescription) { this.policyDescription = policyDescription; }
    public List<Long> getSelectedRoleIds() { return selectedRoleIds; } 
    public void setSelectedRoleIds(List<Long> selectedRoleIds) { this.selectedRoleIds = selectedRoleIds; }
}