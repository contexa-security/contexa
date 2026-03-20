package io.contexa.contexaiam.admin.web.center.dto;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import lombok.Data;

import java.util.Set;

@Data
public class QuickPolicyRequest {
    private String policyName;
    private String description;
    private Set<Long> roleIds;
    private Set<Long> permissionIds;
    private Policy.Effect effect = Policy.Effect.ALLOW;
}
