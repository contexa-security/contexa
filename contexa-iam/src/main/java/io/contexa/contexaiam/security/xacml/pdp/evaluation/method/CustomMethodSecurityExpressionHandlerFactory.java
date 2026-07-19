/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

/**
 * Owns the expression handler used by Contexa method-policy evaluation without
 * exposing it as Spring's application-wide {@code MethodSecurityExpressionHandler}.
 */
public final class CustomMethodSecurityExpressionHandlerFactory {

    private final CustomMethodSecurityExpressionHandler handler;

    public CustomMethodSecurityExpressionHandlerFactory(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            CompositePermissionEvaluator compositePermissionEvaluator,
            RoleHierarchy roleHierarchy,
            PolicyRetrievalPoint policyRetrievalPoint,
            ContextHandler contextHandler,
            AuditLogRepository auditLogRepository,
            ZeroTrustActionRepository actionRedisRepository,
            PolicyCombiningProperties policyCombiningProperties) {
        this.handler = new CustomMethodSecurityExpressionHandler(
                securityZeroTrustProperties,
                compositePermissionEvaluator,
                roleHierarchy,
                policyRetrievalPoint,
                contextHandler,
                auditLogRepository,
                actionRedisRepository,
                policyCombiningProperties);
    }

    public CustomMethodSecurityExpressionHandler getHandler() {
        return handler;
    }
}
