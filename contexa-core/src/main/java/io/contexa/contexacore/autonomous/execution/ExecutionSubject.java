package io.contexa.contexacore.autonomous.execution;

public record ExecutionSubject(
        String subjectType,
        String actorUserId,
        String tenantId,
        String externalSubjectId,
        String principalType,
        HumanSubjectProfile humanProfile,
        ServiceClientSubjectProfile serviceClientProfile,
        DelegatedAgentProfile delegatedAgentProfile) {

    public boolean humanSubject() {
        return ExecutionSubjectTypes.HUMAN_USER.equals(subjectType);
    }

    public boolean serviceClientSubject() {
        return ExecutionSubjectTypes.SERVICE_CLIENT.equals(subjectType);
    }

    public boolean agentSubject() {
        return ExecutionSubjectTypes.AGENT_RUNTIME.equals(subjectType);
    }
}