package io.contexa.contexaiam.admin.web.studio.dto;

/**
 * 권한 부여 마법사 워크플로우가 성공적으로 시작되었음을 알리고,
 * 클라이언트가 다음 단계로 진행하는 데 필요한 정보를 담는 DTO 입니다.
 */
public record WizardInitiationDto(
        String wizardContextId, // 생성된 임시 워크플로우 컨텍스트 ID
        String wizardUrl        // 사용자를 리다이렉트 시킬 마법사 페이지 URL
) {}
