package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;

@RequiredArgsConstructor
public class UserPermissionEvaluator extends AbstractDomainPermissionEvaluator {

    private final ApplicationContext applicationContext;

    @Override
    protected String domain() {
        return "USER";
    }

    @Override
    protected String repositoryBeanName() {
        return "userRepository";
    }

    @Override
    protected ApplicationContext getApplicationContext() {
        return applicationContext;
    }
}
