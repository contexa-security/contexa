/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
