package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import org.springframework.security.core.Authentication;

import java.io.Serializable;

public interface DomainPermissionEvaluator {

    boolean supportsTargetType(String targetType);

    boolean supportsPermission(String permission);

    boolean hasPermission(Authentication auth, Object target, Object permission);

    boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission);

    Object resolveEntity(Serializable targetId);
}
