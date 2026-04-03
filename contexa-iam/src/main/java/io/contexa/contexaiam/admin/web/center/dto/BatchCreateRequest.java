package io.contexa.contexaiam.admin.web.center.dto;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import lombok.Data;

import java.util.List;
import java.util.Set;

@Data
public class BatchCreateRequest {
    private Set<Long> roleIds;
    private Policy.Effect effect = Policy.Effect.ALLOW;
    private List<BatchItem> items;

    @Data
    public static class BatchItem {
        private Long resourceId;
        private Long permissionId;
        private String permissionName;
        private String resourceIdentifier;
        private String resourceType;
        private String httpMethod;
        private Set<String> crudPermissions;
    }
}
