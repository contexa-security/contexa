package io.contexa.contexaiam.admin.web.studio.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * [신규 DTO]
 * 사유: 워크벤치에서 권한 생성 후, 해당 권한을 마법사로 전달하기 위한 DTO.
 *      기존 record에서 일반 클래스로 변경하여 setter 사용이 가능하도록 수정했습니다.
 */
@Data
@NoArgsConstructor
public class InitiateGrantRequestDto {
    private Set<Long> userIds;
    private Set<Long> groupIds;
    private Set<Long> permissionIds;
}