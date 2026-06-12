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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import java.lang.reflect.Method;
import java.util.List;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;

class CustomMethodSecurityExpressionHandlerTest {

    @Test
    @DisplayName("Should resolve method policy identifier from target implementation instead of proxy interface")
    void createEvaluationContext_usesTargetMethodIdentifier() throws Exception {
        PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
        ContextHandler contextHandler = mock(ContextHandler.class);
        AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
        ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        CompositePermissionEvaluator permissionEvaluator = mock(CompositePermissionEvaluator.class);

        when(policyRetrievalPoint.findMethodPolicies(eq(
                EnterpriseProbeService.class.getName() + ".access(String)")))
                .thenReturn(List.of());
        when(contextHandler.create(ArgumentMatchers.any(), ArgumentMatchers.any(MethodInvocation.class)))
                .thenReturn(mock(AuthorizationContext.class));

        CustomMethodSecurityExpressionHandler handler = new CustomMethodSecurityExpressionHandler(
                new SecurityZeroTrustProperties(),
                permissionEvaluator,
                mock(RoleHierarchy.class),
                policyRetrievalPoint,
                contextHandler,
                auditLogRepository,
                actionRepository);

        Method interfaceMethod = ProbeContract.class.getMethod("access", String.class);
        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(interfaceMethod);
        when(invocation.getThis()).thenReturn(new EnterpriseProbeService());
        when(invocation.getArguments()).thenReturn(new Object[]{"resource-001"});

        Authentication authentication = mock(Authentication.class);
        EvaluationContext evaluationContext = handler.createEvaluationContext(() -> authentication, invocation);

        verify(policyRetrievalPoint).findMethodPolicies(
                EnterpriseProbeService.class.getName() + ".access(String)");
        assertThat(evaluationContext.lookupVariable("ownerField")).isEqualTo("resourceId");
    }

    private interface ProbeContract {
        String access(String resourceId);
    }

    private static final class EnterpriseProbeService implements ProbeContract {

        @Override
        @Protectable(ownerField = "resourceId")
        public String access(String resourceId) {
            return resourceId;
        }
    }
}
