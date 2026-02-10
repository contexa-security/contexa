package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

import java.io.Serializable;
import java.util.Comparator;
import java.util.List;

@Slf4j
public class CompositePermissionEvaluator implements PermissionEvaluator {

    private final List<DomainPermissionEvaluator> evaluators;

    public CompositePermissionEvaluator(List<DomainPermissionEvaluator> evaluators) {
        this.evaluators = evaluators.stream()
                .sorted(Comparator.comparingInt(
                        (DomainPermissionEvaluator e) -> ((AbstractDomainPermissionEvaluator) e).domain().length()
                ).reversed())
                .toList();
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (permission != null) {
            String permStr = permission.toString();
            for (DomainPermissionEvaluator evaluator : evaluators) {
                if (evaluator.supportsPermission(permStr)) {
                    return evaluator.hasPermission(authentication, targetDomainObject, permission);
                }
            }
            return false;
        }

        return targetDomainObject != null;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId,
                                 String targetType, Object permissionAction) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        for (DomainPermissionEvaluator evaluator : evaluators) {
            if (evaluator.supportsTargetType(targetType)) {
                return evaluator.hasPermission(authentication, targetId, targetType, permissionAction);
            }
        }

        throw new IllegalArgumentException("No DomainPermissionEvaluator found for targetType: " + targetType);
    }

    public Object resolveEntity(Serializable targetId, String targetType) {
        for (DomainPermissionEvaluator evaluator : evaluators) {
            if (evaluator.supportsTargetType(targetType)) {
                return evaluator.resolveEntity(targetId);
            }
        }
        throw new IllegalArgumentException("No DomainPermissionEvaluator found for targetType: " + targetType);
    }
}
