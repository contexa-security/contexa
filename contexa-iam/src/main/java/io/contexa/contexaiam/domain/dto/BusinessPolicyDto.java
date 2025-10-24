package io.contexa.contexaiam.domain.dto;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import lombok.Data;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
public class BusinessPolicyDto {
    private String policyName;
    private String description;

    // [핵심 수정] 주체(Subject) 대신 역할(Role) ID 목록을 받습니다.
    private Set<Long> roleIds;

    // [핵심 수정] 권한(Permission) ID 목록을 받습니다.
    private Set<Long> permissionIds;

    // [신규] 이 정책이 조건부 정책인지, 단순 역할-권한 할당인지 구분하는 플래그
    private boolean conditional;

    // --- 아래는 지능형 정책 빌더의 상세 조건을 위한 필드 ---
    private Map<Long, List<String>> conditions; // 조건 템플릿 ID와 파라미터
    private boolean aiRiskAssessmentEnabled; // AI 리스크 평가 활성화 여부
    private double requiredTrustScore; // AI 평가 통과에 필요한 최소 신뢰도 점수
    private String customConditionSpel; // 전문가용 커스텀 SpEL
    private Policy.Effect effect = Policy.Effect.ALLOW; // 기본값은 허용
}