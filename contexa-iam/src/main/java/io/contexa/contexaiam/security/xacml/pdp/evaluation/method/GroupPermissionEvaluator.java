package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;

@RequiredArgsConstructor
public class GroupPermissionEvaluator extends AbstractDomainPermissionEvaluator {

    private final ApplicationContext applicationContext;

    @Override
    protected String domain() {
        return "GROUP";
    }

    @Override
    protected String repositoryBeanName() {
        return "groupRepository";
    }

    @Override
    protected ApplicationContext getApplicationContext() {
        return applicationContext;
    }
}
