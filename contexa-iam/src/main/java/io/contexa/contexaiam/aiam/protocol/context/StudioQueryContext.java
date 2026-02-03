package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;

@Getter
@Setter
public class StudioQueryContext extends DomainContext {

    private Map<String, Object> queryMetadata;
    private String organizationStructure;
    private List<String> availableTeams;
    private List<String> availableGroups;
    private Map<String, Object> businessContext;

    private List<String> availableRoles;
    private List<String> availablePermissions;
    private List<String> availableResources;
    private Map<String, Set<String>> rolePermissionMap;
    private Map<String, Set<String>> userRoleMap;
    private Map<String, Set<String>> groupMemberMap;

    private boolean includeVisualization = true;
    private boolean includeRecommendations = true;
    private int maxResultCount = 50;

    public StudioQueryContext() {
        super();
        this.businessContext = new HashMap<>();
        this.queryMetadata = new HashMap<>();
    }

    @Override
    public String getDomainType() {
        return "STUDIO_QUERY";
    }

    public static class Builder {
        public Builder() {}
        public StudioQueryContext build() {
            return new StudioQueryContext();
        }
    }
}
