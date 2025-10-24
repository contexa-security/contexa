package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import lombok.Data;
import java.util.List;
import java.util.Set;

/**
 * [신규] 권한 부여 마법사의 최종 commit 요청을 위한 타입-안전(type-safe) DTO
 */
@Data
public class CommitWizardRequest {
    private String policyName;
    private String policyDescription;
    private List<Long> selectedRoleIds;
    private Set<Long> permissionIds;
}