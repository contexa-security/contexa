package io.contexa.demo.security.policy;

import io.contexa.demo.security.policy.dto.PolicyRule;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.List;

public interface LabSecurityPolicy {

    List<PolicyRule> rules();

    void apply(HttpSecurity http, AuthorizationManager<RequestAuthorizationContext> platform) throws Exception;
}
