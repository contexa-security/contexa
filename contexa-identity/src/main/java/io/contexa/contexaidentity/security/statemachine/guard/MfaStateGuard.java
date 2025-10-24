package io.contexa.contexaidentity.security.statemachine.guard;

/**
 * MFA State Guard 인터페이스
 */
public interface MfaStateGuard {

    /**
     * Guard 이름 반환
     */
    String getGuardName();

    /**
     * Guard 실패 사유 반환
     */
    String getFailureReason();
}