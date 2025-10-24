package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.List;

/**
 * [최종] 중복 정책 정보를 담는 DTO 입니다.
 * @param reason 중복으로 판단된 이유
 * @param policyIds 중복되는 정책들의 ID 목록
 * @param policySignature 정책의 고유 서명 (디버깅용)
 */
public record DuplicatePolicyDto(String reason, List<Long> policyIds, String policySignature) {}