package io.contexa.contexaidentity.security.core.mfa.context;

import java.util.Objects;


public record FactorIdentifier(String flowName, String stepId) {
    

    public FactorIdentifier(String flowName, String stepId) {
        this.flowName = Objects.requireNonNull(flowName, "flowName cannot be null").toLowerCase();
        this.stepId = Objects.requireNonNull(stepId, "stepId cannot be null"); 
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
