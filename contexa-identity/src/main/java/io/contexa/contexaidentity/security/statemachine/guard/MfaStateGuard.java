package io.contexa.contexaidentity.security.statemachine.guard;

public interface MfaStateGuard {

    String getGuardName();

    String getFailureReason();
}