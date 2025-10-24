package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * [신규 DTO]
 * 권한 할당 변경사항(Delta)을 담는 DTO.
 * 시뮬레이션 및 최종 커밋에 사용됩니다.
 */
/**
 * [오류 수정]
 * Spring MVC의 데이터 바인딩을 위해 컬렉션 타입을 Set에서 List로 변경합니다.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AssignmentChangeDto {

    private List<Assignment> added = new ArrayList<>(); // Set -> List로 변경
    private List<Long> removedGroupIds = new ArrayList<>(); // Set -> List로 변경
    private List<Long> removedRoleIds = new ArrayList<>(); // Set -> List로 변경

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Assignment {
        @NotNull
        private Long targetId;
        @NotBlank
        private String targetType;
        private LocalDateTime validUntil;
    }
}
