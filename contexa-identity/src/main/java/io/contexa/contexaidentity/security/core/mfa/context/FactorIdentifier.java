package io.contexa.contexaidentity.security.core.mfa.context;

import java.util.Objects;

/**
 * FeatureRegistry 에서 인증 단계별 Filter를 고유하게 식별하기 위한 키입니다.
 * flowName: 해당 인증 단계가 속한 AuthenticationFlowConfig의 typeName (예: "single-form", "mfa-main").
 * stepId: 해당 AuthenticationFlowConfig 내에서 각 AuthenticationStepConfig의 고유 ID.
 */
public record FactorIdentifier(String flowName, String stepId) {
    // factorType은 stepId 생성 시 포함되거나, 필요시 별도 멤버로 추가 가능

    public FactorIdentifier(String flowName, String stepId) {
        this.flowName = Objects.requireNonNull(flowName, "flowName cannot be null").toLowerCase();
        this.stepId = Objects.requireNonNull(stepId, "stepId cannot be null"); // stepId는 대소문자 구분 가능
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FactorIdentifier that = (FactorIdentifier) o;
        return flowName.equals(that.flowName) && stepId.equals(that.stepId);
    }

    @Override
    public String toString() {
        return "FactorIdentifier{" +
                "flowName='" + flowName + '\'' +
                ", stepId='" + stepId + '\'' +
                '}';
    }

    public static FactorIdentifier of(String flowName, String stepId) {
        return new FactorIdentifier(flowName, stepId);
    }
}
