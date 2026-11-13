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
package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexaiam.common.event.dto.RolePermissionsChangedEvent;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AuthorityProbe;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.event.TransactionalEventListenerFactory;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PolicySynchronizationServiceTest {

    private final PolicyRepository policyRepository = mock(PolicyRepository.class);
    private final RoleRepository roleRepository = mock(RoleRepository.class);
    private final PolicyService policyService = mock(PolicyService.class);

    @Test
    @DisplayName("the policy of a role is made after the role's transaction commits, from what it committed")
    void thePolicyIsMadeAfterTheRolesTransactionCommits() {
        when(policyRepository.findByName(anyString())).thenReturn(Optional.empty());
        when(roleRepository.findByIdWithPermissionsAndResources(7L)).thenReturn(Optional.of(role("ROLE_SALES", "READ", true)));

        try (AnnotationConfigApplicationContext context = context()) {
            new TransactionTemplate(new InMemoryTransactions()).executeWithoutResult(status -> {
                context.publishEvent(new RolePermissionsChangedEvent(7L));
                verify(roleRepository, never()).findByIdWithPermissionsAndResources(anyLong());
            });

            verify(roleRepository).findByIdWithPermissionsAndResources(7L);
            verify(policyService).createPolicy(any(PolicyDto.class));
        }
    }

    @Test
    @DisplayName("a role whose transaction rolls back makes no policy")
    void aRoleWhoseTransactionRollsBackMakesNoPolicy() {
        try (AnnotationConfigApplicationContext context = context()) {
            new TransactionTemplate(new InMemoryTransactions()).executeWithoutResult(status -> {
                context.publishEvent(new RolePermissionsChangedEvent(7L));
                status.setRollbackOnly();
            });

            verify(roleRepository, never()).findByIdWithPermissionsAndResources(anyLong());
            verify(policyService, never()).createPolicy(any(PolicyDto.class));
        }
    }

    @Test
    @DisplayName("a role and a permission named to end their literal are each asked for as they are, the role by its authority")
    void namesThatWouldEndTheirLiteralAreAskedForAsTheyAre() {
        String name = AuthorityProbe.ALWAYS_TRUE_NAME;
        String given = RoleAuthority.authorityOf(name);
        when(policyRepository.findByName(anyString())).thenReturn(Optional.empty());
        when(roleRepository.findByIdWithPermissionsAndResources(7L)).thenReturn(Optional.of(role(name, name, true)));

        new PolicySynchronizationService(policyRepository, roleRepository, policyService)
                .handleRolePermissionsChange(new RolePermissionsChangedEvent(7L));

        ArgumentCaptor<PolicyDto> captor = ArgumentCaptor.forClass(PolicyDto.class);
        verify(policyService).createPolicy(captor.capture());
        String expression = captor.getValue().getRules().get(0).getConditions().get(0).getExpression();

        AuthorityProbe.Outcome nobody = AuthorityProbe.evaluate(expression, "R&D", "Ops");
        assertThat(nobody.granted()).isFalse();
        assertThat(nobody.asked()).containsExactly(given);
        AuthorityProbe.Outcome holder = AuthorityProbe.evaluate(expression, given, name);
        assertThat(holder.granted()).isTrue();
        assertThat(holder.asked()).containsExactly(given, name);
    }

    @Test
    @DisplayName("a role that does not start with ROLE_ is asked for as the authority it gives its users")
    void aRoleWithoutThePrefixIsAskedForAsTheAuthorityItGives() {
        for (String roleName : List.of("O'Neil", "sales", "R&D")) {
            clearInvocations(policyService);
            when(policyRepository.findByName(anyString())).thenReturn(Optional.empty());
            Role role = role(roleName, "READ", true);
            when(roleRepository.findByIdWithPermissionsAndResources(7L)).thenReturn(Optional.of(role));
            String given = new RoleAuthority(role).getAuthority();

            new PolicySynchronizationService(policyRepository, roleRepository, policyService)
                    .handleRolePermissionsChange(new RolePermissionsChangedEvent(7L));

            ArgumentCaptor<PolicyDto> captor = ArgumentCaptor.forClass(PolicyDto.class);
            verify(policyService).createPolicy(captor.capture());
            String expression = captor.getValue().getRules().get(0).getConditions().get(0).getExpression();
            AuthorityProbe.Outcome holder = AuthorityProbe.evaluate(expression, given, "READ");
            assertThat(holder.granted()).as("a user who holds " + given).isTrue();
            assertThat(holder.asked()).containsExactly(given, "READ");
            assertThat(AuthorityProbe.evaluate(expression, "ROLE_OTHER", "READ").granted()).isFalse();
        }
    }

    @Test
    @DisplayName("D31: the automatic policy names the role, not its description in another language")
    void theDescriptionNamesTheRoleNotItsDescription() {
        when(policyRepository.findByName(anyString())).thenReturn(Optional.empty());
        Role role = role("ROLE_USER", "READ", true);
        role.setRoleDesc("일반 사용자 역할");
        when(roleRepository.findByIdWithPermissionsAndResources(7L)).thenReturn(Optional.of(role));

        new PolicySynchronizationService(policyRepository, roleRepository, policyService)
                .handleRolePermissionsChange(new RolePermissionsChangedEvent(7L));

        ArgumentCaptor<PolicyDto> captor = ArgumentCaptor.forClass(PolicyDto.class);
        verify(policyService).createPolicy(captor.capture());
        assertThat(captor.getValue().getName()).isEqualTo("AUTO_POLICY_FOR_ROLE_USER");
        assertThat(captor.getValue().getDescription()).isEqualTo("Auto-synchronized policy for role 'ROLE_USER'");
        assertThat(captor.getValue().getRules().get(0).getDescription()).isEqualTo("Auto-sync rule for ROLE_USER");
    }

    @Test
    @DisplayName("a role that starts with ROLE_ is asked for by its name, as before")
    void aRoleWithThePrefixIsAskedForByItsName() {
        when(policyRepository.findByName(anyString())).thenReturn(Optional.empty());
        when(roleRepository.findByIdWithPermissionsAndResources(7L)).thenReturn(Optional.of(role("ROLE_SALES", "READ", true)));

        new PolicySynchronizationService(policyRepository, roleRepository, policyService)
                .handleRolePermissionsChange(new RolePermissionsChangedEvent(7L));

        ArgumentCaptor<PolicyDto> captor = ArgumentCaptor.forClass(PolicyDto.class);
        verify(policyService).createPolicy(captor.capture());
        assertThat(captor.getValue().getRules().get(0).getConditions().get(0).getExpression())
                .isEqualTo("hasAuthority('ROLE_SALES') and (hasAuthority('READ'))");
    }

    @Test
    @DisplayName("a role whose permissions guard no resource has no policy to make, and that is not an error")
    void aRoleWithoutAResourceMakesNoPolicyAndRaisesNothing() {
        when(policyRepository.findByName(anyString())).thenReturn(Optional.empty());
        when(roleRepository.findByIdWithPermissionsAndResources(7L)).thenReturn(Optional.of(role("ROLE_SALES", "READ", false)));
        // a policy needs a target: the policy service refuses to make one without it
        doThrow(new IllegalArgumentException("a policy needs at least one target"))
                .when(policyService).createPolicy(any(PolicyDto.class));

        assertThatCode(() -> new PolicySynchronizationService(policyRepository, roleRepository, policyService)
                .handleRolePermissionsChange(new RolePermissionsChangedEvent(7L))).doesNotThrowAnyException();

        verify(policyService, never()).createPolicy(any(PolicyDto.class));
        verify(policyService, never()).updatePolicy(any(PolicyDto.class));
    }

    @Test
    @DisplayName("D42: a role that loses the last permission guarding a resource has its automatic policy deleted")
    void aRoleThatLosesItsLastResourceHasItsPolicyDeleted() {
        Policy existing = Policy.builder().id(41L).name("AUTO_POLICY_FOR_ROLE_SALES").build();
        when(policyRepository.findByName("AUTO_POLICY_FOR_ROLE_SALES")).thenReturn(Optional.of(existing));
        when(roleRepository.findByIdWithPermissionsAndResources(7L)).thenReturn(Optional.of(role("ROLE_SALES", "READ", false)));

        new PolicySynchronizationService(policyRepository, roleRepository, policyService)
                .handleRolePermissionsChange(new RolePermissionsChangedEvent(7L));

        verify(policyService).deleteAutomaticPolicy(eq(41L), anyString());
        verify(policyService, never()).deletePolicy(any(), any());
        verify(policyService, never()).updatePolicy(any(PolicyDto.class));
        verify(policyService, never()).createPolicy(any(PolicyDto.class));
    }

    private AnnotationConfigApplicationContext context() {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.registerBean(TransactionalEventListenerFactory.class);
        context.registerBean(PolicySynchronizationService.class,
                () -> new PolicySynchronizationService(policyRepository, roleRepository, policyService));
        context.refresh();
        return context;
    }

    private static Role role(String roleName, String permissionName, boolean guardsAResource) {
        ManagedResource resource = guardsAResource ? ManagedResource.builder()
                .resourceIdentifier("/rc/one/1").resourceType(ManagedResource.ResourceType.URL)
                .httpMethod(ManagedResource.HttpMethod.GET).friendlyName("one").build() : null;
        Permission permission = Permission.builder().id(3L).name(permissionName).managedResource(resource).build();
        Role role = Role.builder().id(7L).roleName(roleName).roleDesc("desc").build();
        role.setRolePermissions(Set.of(RolePermission.builder().role(role).permission(permission).build()));
        return role;
    }

    /** A transaction manager that keeps nothing: what matters here is when its transactions commit or roll back. */
    private static final class InMemoryTransactions extends AbstractPlatformTransactionManager {

        @Override
        protected Object doGetTransaction() {
            return new Object();
        }

        @Override
        protected void doBegin(Object transaction, TransactionDefinition definition) {
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
        }
    }
}
