/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.expression.MethodBasedEvaluationContext;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class CustomMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final ContextHandler contextHandler;
    private final AuditLogRepository auditLogRepository;
    private final ZeroTrustActionRepository actionRedisRepository;
    private final PolicyCombiningProperties policyCombiningProperties;

    public CustomMethodSecurityExpressionHandler(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            CompositePermissionEvaluator compositePermissionEvaluator,
            RoleHierarchy roleHierarchy,
            PolicyRetrievalPoint policyRetrievalPoint,
            ContextHandler contextHandler,
            AuditLogRepository auditLogRepository,
            ZeroTrustActionRepository actionRedisRepository) {
        this(securityZeroTrustProperties, compositePermissionEvaluator, roleHierarchy,
                policyRetrievalPoint, contextHandler, auditLogRepository, actionRedisRepository,
                new PolicyCombiningProperties());
    }

    public CustomMethodSecurityExpressionHandler(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            CompositePermissionEvaluator compositePermissionEvaluator,
            RoleHierarchy roleHierarchy,
            PolicyRetrievalPoint policyRetrievalPoint,
            ContextHandler contextHandler,
            AuditLogRepository auditLogRepository,
            ZeroTrustActionRepository actionRedisRepository,
            PolicyCombiningProperties policyCombiningProperties) {
        Assert.notNull(policyRetrievalPoint, "PolicyRetrievalPoint cannot be null");
        Assert.notNull(securityZeroTrustProperties, "SecurityZeroTrustProperties cannot be null");
        this.policyRetrievalPoint = policyRetrievalPoint;
        this.contextHandler = contextHandler;
        this.auditLogRepository = auditLogRepository;
        this.actionRedisRepository = actionRedisRepository;
        this.policyCombiningProperties = policyCombiningProperties != null
                ? policyCombiningProperties : new PolicyCombiningProperties();
        super.setPermissionEvaluator(compositePermissionEvaluator);
        super.setRoleHierarchy(roleHierarchy);
    }

    @Override
    public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication, MethodInvocation mi) {
        Method method = resolveSpecificMethod(mi);
        String ownerField = extractOwnerFieldFromMethod(method);
        Authentication auth = authentication.get();
        AuthorizationContext authorizationContext = contextHandler.create(auth, mi);

        CustomMethodSecurityExpressionRoot root = new CustomMethodSecurityExpressionRoot(
                auth, authorizationContext, auditLogRepository, actionRedisRepository);
        root.setOwnerField(ownerField);
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(getTrustResolver());
        root.setRoleHierarchy(getRoleHierarchy());
        root.setDefaultRolePrefix(getDefaultRolePrefix());
        root.setThis(mi.getThis());

        MethodBasedEvaluationContext ctx = new MethodBasedEvaluationContext(
                root, method, mi.getArguments(), getParameterNameDiscoverer());
        ctx.setBeanResolver(getBeanResolver());
        ctx.setVariable("ai", root);
        if (StringUtils.hasText(ownerField)) {
            ctx.setVariable("ownerField", ownerField);
        }

        String params = Arrays.stream(method.getParameterTypes())
                .map(Class::getSimpleName)
                .collect(Collectors.joining(","));
        String methodIdentifier = String.format("%s.%s(%s)",
                method.getDeclaringClass().getName(), method.getName(), params);

        List<Policy> policies = policyRetrievalPoint.findMethodPolicies(methodIdentifier);
        ctx.setVariable("methodPolicyPlan", buildPolicyPlan(policies));
        return ctx;
    }

    private Method resolveSpecificMethod(MethodInvocation mi) {
        Method method = mi.getMethod();
        Object target = mi.getThis();
        if (target == null) {
            return method;
        }
        Class<?> targetClass = AopProxyUtils.ultimateTargetClass(target);
        return targetClass == null ? method : AopUtils.getMostSpecificMethod(method, targetClass);
    }

    private String extractOwnerFieldFromMethod(Method method) {
        Protectable protectable = method.getAnnotation(Protectable.class);
        return protectable != null && StringUtils.hasText(protectable.ownerField())
                ? protectable.ownerField() : null;
    }

    private MethodPolicyPlan buildPolicyPlan(List<Policy> policies) {
        List<Policy> executablePolicies = CollectionUtils.isEmpty(policies)
                ? List.of()
                : policies.stream()
                .filter(this::isExecutable)
.sorted(Comparator.comparingInt(this::targetOrder)
                        .thenComparingInt(Policy::getPriority)
                        .thenComparing(Policy::getId, Comparator.nullsLast(Long::compareTo)))
                .toList();
        List<Expression> expressions = executablePolicies.stream()
                .map(this::buildPolicyExpression)
.map(getExpressionParser()::parseExpression)
.toList();
        List<MethodPolicyMetadata> metadata = executablePolicies.stream()
                .map(policy -> new MethodPolicyMetadata(
                        policy.getId(), policy.getEffect(), policy.getPriority()))
                .toList();
        return new MethodPolicyPlan(
                expressions,
                policyCombiningProperties.getCombiningAlgorithm(),
                policyCombiningProperties.getMissingMethodPolicyDecision(),
                metadata);
    }

    private boolean isExecutable(Policy policy) {
        if (policy == null || !policy.getIsActive()) {
            return false;
        }
        return policy.getApprovalStatus() == Policy.ApprovalStatus.APPROVED
                || policy.getApprovalStatus() == Policy.ApprovalStatus.NOT_REQUIRED;
    }

    private int targetOrder(Policy policy) {
        return policy.getTargets().stream()
                .filter(target -> "METHOD".equals(target.getTargetType()))
                .mapToInt(target -> target.getTargetOrder())
                .min()
                .orElse(Integer.MAX_VALUE);
    }

    private String buildPolicyExpression(Policy policy) {
        String conditionExpression = policy.getRules().stream()
                .flatMap(rule -> rule.getConditions().stream())
                .map(condition -> "(" + condition.getExpression() + ")")
                .collect(Collectors.joining(" and "));
        if (conditionExpression.isEmpty()) {
            return policy.getEffect() == Policy.Effect.ALLOW ? "true" : "false";
        }
        return policy.getEffect() == Policy.Effect.DENY
                ? "!(" + conditionExpression + ")" : conditionExpression;
    }
}
