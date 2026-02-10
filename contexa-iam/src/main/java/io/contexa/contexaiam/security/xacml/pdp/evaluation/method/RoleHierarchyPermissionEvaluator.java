package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;

@RequiredArgsConstructor
public class RoleHierarchyPermissionEvaluator extends AbstractDomainPermissionEvaluator {

    private final ApplicationContext applicationContext;

    @Override
    protected String domain() {
        return "ROLE_HIERARCHY";
    }

    @Override
    protected String repositoryBeanName() {
        return "roleHierarchyRepository";
    }

    @Override
    protected ApplicationContext getApplicationContext() {
        return applicationContext;
    }
}
