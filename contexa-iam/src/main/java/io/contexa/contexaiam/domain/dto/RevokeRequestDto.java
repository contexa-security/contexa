package io.contexa.contexaiam.domain.dto;

public record RevokeRequestDto(
        Long policyId,               // 회수할 권한의 근거가 되는 정책 ID
        String revokeReason          // 권한 회수 사유 (감사 로그용)
) {}
