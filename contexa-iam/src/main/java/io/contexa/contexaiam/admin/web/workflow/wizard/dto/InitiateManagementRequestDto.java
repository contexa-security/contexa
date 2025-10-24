package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import lombok.Data;
import org.antlr.v4.runtime.misc.NotNull;

/**
 * [신규 DTO]
 * 주체(사용자/그룹)에 대한 권한 관리 세션을 시작하기 위해 필요한 정보를 전달합니다.
 */
@Data
public class InitiateManagementRequestDto {

    @NotNull
    private Long subjectId;

//    @NotBlank
    private String subjectType; // "USER" 또는 "GROUP"
}
