package io.contexa.contexacore.autonomous.context;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleScopeSnapshot {

    private String summary;

    private String currentResourceFamily;

    private String currentActionFamily;

    @Builder.Default
    private List<String> expectedResourceFamilies = new ArrayList<>();

    @Builder.Default
    private List<String> expectedActionFamilies = new ArrayList<>();

    @Builder.Default
    private List<String> forbiddenResourceFamilies = new ArrayList<>();

    @Builder.Default
    private List<String> forbiddenActionFamilies = new ArrayList<>();

    @Builder.Default
    private List<String> normalApprovalPatterns = new ArrayList<>();

    @Builder.Default
    private List<String> normalEscalationPatterns = new ArrayList<>();

    @Builder.Default
    private List<String> recentPermissionChanges = new ArrayList<>();

    private Boolean resourceFamilyDrift;

    private Boolean actionFamilyDrift;

    private Boolean temporaryElevation;

    private String temporaryElevationReason;

    private Boolean elevatedPrivilegeWindowActive;

    private String elevationWindowSummary;

    private ContextTrustProfile trustProfile;
}
