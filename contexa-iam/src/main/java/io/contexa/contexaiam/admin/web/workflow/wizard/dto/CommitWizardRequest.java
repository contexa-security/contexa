package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import lombok.Data;
import java.util.List;
import java.util.Set;


@Data
public class CommitWizardRequest {
    private String policyName;
    private String policyDescription;
    private List<Long> selectedRoleIds;
    private Set<Long> permissionIds;
}