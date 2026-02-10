package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;

@RequiredArgsConstructor
public class RolePermissionEvaluator extends AbstractDomainPermissionEvaluator {

    private final ApplicationContext applicationContext;

    @Override
    protected String domain() {
        return "ROLE";
    }

    @Override
    protected String repositoryBeanName() {
        return "roleRepository";
    }

    @Override
    protected ApplicationContext getApplicationContext() {
        return applicationContext;
    }
}
