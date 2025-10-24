package io.contexa.contexaiam.domain.dto;

import java.util.Set;

/**
 * [최종 정의] 정책 빌더 UI에 조건 템플릿 정보를 전달하기 위한 DTO.
 * 호환성 여부와 SpEL 템플릿 원본을 포함합니다.
 */
public record ConditionTemplateDto(
        Long id,
        String name,
        String description,
        Set<String> requiredVariables, // SpEL에 필요한 변수 목록 (예: [#targetObject])
        boolean isCompatible,          // 현재 리소스 컨텍스트와 호환되는지 여부
        String spelTemplate           // JavaScript 에서 AI 검증 시 사용할 SpEL 원본
) {}