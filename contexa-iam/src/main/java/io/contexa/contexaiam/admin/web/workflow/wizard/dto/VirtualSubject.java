package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Users;
import lombok.Getter;
import java.util.Set;


@Getter
public class VirtualSubject {
    private final Users originalUser;
    private final Set<Group> virtualGroups; 

    public VirtualSubject(Users originalUser, Set<Group> virtualGroups) {
        this.originalUser = originalUser;
        this.virtualGroups = virtualGroups;
    }
}
