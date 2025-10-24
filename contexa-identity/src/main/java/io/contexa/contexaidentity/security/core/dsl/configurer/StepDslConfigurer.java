package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;

public interface StepDslConfigurer {
    AuthenticationStepConfig toConfig();
    int getOrder();
    StepDslConfigurer order(int order);

}
