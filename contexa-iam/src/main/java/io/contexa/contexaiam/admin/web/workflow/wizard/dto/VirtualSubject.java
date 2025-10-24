package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Users;
import lombok.Getter;
import java.util.Set;

/**
 * [신규 모델]
 * DB에 커밋되지 않은 변경사항을 반영한 가상 주체(사용자) 모델.
 * 권한 시뮬레이션에 사용됩니다.
 */
@Getter
public class VirtualSubject {
    private final Users originalUser;
    private final Set<Group> virtualGroups; // 가상으로 소속된 그룹 목록

    public VirtualSubject(Users originalUser, Set<Group> virtualGroups) {
        this.originalUser = originalUser;
        this.virtualGroups = virtualGroups;
    }
}
