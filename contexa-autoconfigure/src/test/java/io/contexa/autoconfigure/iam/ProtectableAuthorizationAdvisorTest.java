/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 */
package io.contexa.autoconfigure.iam;

import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.service.AuthorizationDenialRecorder;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pep.ProtectableLlmSuppressionWriter;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import io.contexa.contexaiam.security.xacml.pep.ProtectableResourceCertificationGate;
import org.junit.jupiter.api.Test;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Role;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The @Protectable method advisor is created while post-processors are registered (the auto-proxy creator looks its
 * advisors up then), so it resolves none of its collaborators at its creation: resolving them then made their whole
 * graph (the decision service, the language models, the data sources) miss the post-processors not yet registered.
 */
class ProtectableAuthorizationAdvisorTest {

    @Test
    void theAdvisorResolvesNoCollaboratorWhenItIsCreatedAndEachOnceAfterTheSingletons() {
        AtomicInteger resolved = new AtomicInteger();

        AuthorizationManagerMethodInterceptor advisor = IamInfrastructureAutoConfiguration.protectableAuthorizationAdvisor(
                counting(mock(ProtectableMethodAuthorizationManager.class), resolved),
                counting(mock(ProtectableRapidReentryGuard.class), resolved),
                counting(mock(ZeroTrustEventPublisher.class), resolved),
                counting(mock(SynchronousProtectableDecisionService.class), resolved),
                counting(mock(ProtectableResourceCertificationGate.class), resolved),
                counting(mock(ProtectableLlmSuppressionWriter.class), resolved),
                counting(mock(AuthorizationDenialRecorder.class), resolved),
                counting(new SecurityZeroTrustProperties(), resolved));

        assertThat(resolved).as("nothing is resolved while post-processors are registered").hasValue(0);

        advisor.afterSingletonsInstantiated();
        advisor.afterSingletonsInstantiated();

        assertThat(resolved).as("each collaborator once").hasValue(8);
    }

    @Test
    void theAdvisorBeanMethodIsStaticAndAnInfrastructureRole() throws NoSuchMethodException {
        Method method = Arrays.stream(IamInfrastructureAutoConfiguration.class.getDeclaredMethods())
                .filter(each -> each.getName().equals("protectableAuthorizationAdvisor"))
                .findFirst().orElseThrow();

        assertThat(Modifier.isStatic(method.getModifiers())).isTrue();
        assertThat(method.getAnnotation(Role.class).value()).isEqualTo(BeanDefinition.ROLE_INFRASTRUCTURE);
    }

    /** A provider that counts how often it hands its object out. */
    static <T> ObjectProvider<T> counting(T object, AtomicInteger resolved) {
        return new ObjectProvider<>() {
            @Override
            public T getObject() {
                resolved.incrementAndGet();
                return object;
            }

            @Override
            public T getObject(Object... args) {
                return getObject();
            }

            @Override
            public T getIfAvailable() {
                return getObject();
            }

            @Override
            public T getIfUnique() {
                return getObject();
            }
        };
    }
}
