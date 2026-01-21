package io.contexa.contexaidentity.security.core.mfa.context;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexacommon.enums.AuthType;

import java.util.List;
import java.util.Set;

public interface FactorContextExtensions {

    int getRetryCount();

    Set<AuthType> getAvailableFactors();

    List<AuthenticationStepConfig> getCompletedFactors();

    String getLastError();

    long getCreatedAt();
}