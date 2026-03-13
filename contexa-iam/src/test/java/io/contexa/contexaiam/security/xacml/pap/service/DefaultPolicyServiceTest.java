package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexaiam.common.event.dto.PolicyChangedEvent;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultPolicyServiceTest {

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private PolicyRetrievalPoint policyRetrievalPoint;

    @Mock
    private CustomDynamicAuthorizationManager authorizationManager;

    @Mock
    private PolicyEnrichmentService policyEnrichmentService;

    @Mock
    private IntegrationEventBus eventBus;

    @Mock
    private PermissionRepository permissionRepository;

    @InjectMocks
    private DefaultPolicyService policyService;

    @Nested
    @DisplayName("Policy creation")
    class PolicyCreation {

        @Test
        @DisplayName("should create policy from DTO and save to repository")
        void shouldCreatePolicyFromDto() {
            // given
            PolicyDto dto = createSimplePolicyDto("test-policy", "Test description");
            Policy savedPolicy = createPolicyEntity(1L, "test-policy");
            when(policyRepository.save(any(Policy.class))).thenReturn(savedPolicy);
            when(permissionRepository.findAllByNameIn(anySet())).thenReturn(Collections.emptyList());

            // when
            Policy result = policyService.createPolicy(dto);

            // then
            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("test-policy");
            verify(policyRepository).save(any(Policy.class));
            verify(policyEnrichmentService).enrichPolicyWithFriendlyDescription(any(Policy.class));
        }

        @Test
        @DisplayName("should reload authorization system after policy creation")
        void shouldReloadAuthorizationAfterCreate() {
            // given
            PolicyDto dto = createSimplePolicyDto("reload-test", "Reload test");
            Policy savedPolicy = createPolicyEntity(2L, "reload-test");
            when(policyRepository.save(any(Policy.class))).thenReturn(savedPolicy);
            when(permissionRepository.findAllByNameIn(anySet())).thenReturn(Collections.emptyList());

            // when
            policyService.createPolicy(dto);

            // then
            verify(policyRetrievalPoint).clearUrlPoliciesCache();
            verify(policyRetrievalPoint).clearMethodPoliciesCache();
            verify(authorizationManager).reload();
        }

        @Test
        @DisplayName("should publish PolicyChangedEvent with extracted permission IDs")
        void shouldPublishPolicyChangedEventWithPermissions() {
            // given
            PolicyDto dto = createPolicyDtoWithCondition("perm-policy", "hasAuthority('READ_USER')");

            Policy savedPolicy = createPolicyWithCondition(3L, "perm-policy", "hasAuthority('READ_USER')");
            when(policyRepository.save(any(Policy.class))).thenReturn(savedPolicy);

            Permission perm = mock(Permission.class);
            when(perm.getId()).thenReturn(100L);
            when(permissionRepository.findAllByNameIn(Set.of("READ_USER"))).thenReturn(List.of(perm));

            // when
            policyService.createPolicy(dto);

            // then
            ArgumentCaptor<PolicyChangedEvent> eventCaptor = ArgumentCaptor.forClass(PolicyChangedEvent.class);
            verify(eventBus).publish(eventCaptor.capture());
            PolicyChangedEvent event = eventCaptor.getValue();
            assertThat(event.getPolicyId()).isEqualTo(3L);
            assertThat(event.getPermissionIds()).contains(100L);
        }

        @Test
        @DisplayName("should not publish event when no permissions found in conditions")
        void shouldNotPublishEventWithoutPermissions() {
            // given
            PolicyDto dto = createSimplePolicyDto("no-perm-policy", "No permissions");
            Policy savedPolicy = createPolicyEntity(4L, "no-perm-policy");
            when(policyRepository.save(any(Policy.class))).thenReturn(savedPolicy);

            // when
            policyService.createPolicy(dto);

            // then
            verify(eventBus, never()).publish(any(PolicyChangedEvent.class));
        }
    }

    @Nested
    @DisplayName("Policy update")
    class PolicyUpdate {

        @Test
        @DisplayName("should find existing policy and update from DTO")
        void shouldFindExistingAndUpdate() {
            // given
            PolicyDto dto = createSimplePolicyDto("update-policy", "Updated desc");
            dto.setId(10L);

            Policy existingPolicy = createPolicyEntityWithCollections(10L, "old-name");
            when(policyRepository.findByIdWithDetails(10L)).thenReturn(Optional.of(existingPolicy));
            when(policyRepository.save(any(Policy.class))).thenReturn(existingPolicy);
            when(permissionRepository.findAllByNameIn(anySet())).thenReturn(Collections.emptyList());

            // when
            policyService.updatePolicy(dto);

            // then
            verify(policyRepository).findByIdWithDetails(10L);
            verify(policyRepository).save(existingPolicy);
            verify(policyEnrichmentService).enrichPolicyWithFriendlyDescription(existingPolicy);
            assertThat(existingPolicy.getName()).isEqualTo("update-policy");
            assertThat(existingPolicy.getDescription()).isEqualTo("Updated desc");
        }

        @Test
        @DisplayName("should throw exception when updating non-existent policy")
        void shouldThrowWhenPolicyNotFound() {
            // given
            PolicyDto dto = createSimplePolicyDto("missing", "desc");
            dto.setId(999L);
            when(policyRepository.findByIdWithDetails(999L)).thenReturn(Optional.empty());

            // when/then
            assertThatThrownBy(() -> policyService.updatePolicy(dto))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("999");
        }

        @Test
        @DisplayName("should reload authorization system after policy update")
        void shouldReloadAfterUpdate() {
            // given
            PolicyDto dto = createSimplePolicyDto("reload-update", "desc");
            dto.setId(11L);
            Policy existing = createPolicyEntityWithCollections(11L, "reload-update");
            when(policyRepository.findByIdWithDetails(11L)).thenReturn(Optional.of(existing));
            when(policyRepository.save(any(Policy.class))).thenReturn(existing);
            when(permissionRepository.findAllByNameIn(anySet())).thenReturn(Collections.emptyList());

            // when
            policyService.updatePolicy(dto);

            // then
            verify(policyRetrievalPoint).clearUrlPoliciesCache();
            verify(policyRetrievalPoint).clearMethodPoliciesCache();
            verify(authorizationManager).reload();
        }
    }

    @Nested
    @DisplayName("Policy deletion")
    class PolicyDeletion {

        @Test
        @DisplayName("should delete policy by ID and publish event")
        void shouldDeleteAndPublishEvent() {
            // when
            policyService.deletePolicy(50L);

            // then
            verify(policyRepository).deleteById(50L);
            ArgumentCaptor<PolicyChangedEvent> captor = ArgumentCaptor.forClass(PolicyChangedEvent.class);
            verify(eventBus).publish(captor.capture());
            assertThat(captor.getValue().getPolicyId()).isEqualTo(50L);
            assertThat(captor.getValue().getPermissionIds()).isEmpty();
        }

        @Test
        @DisplayName("should reload authorization system after deletion")
        void shouldReloadAfterDelete() {
            // when
            policyService.deletePolicy(51L);

            // then
            verify(policyRetrievalPoint).clearUrlPoliciesCache();
            verify(policyRetrievalPoint).clearMethodPoliciesCache();
            verify(authorizationManager).reload();
        }
    }

    @Nested
    @DisplayName("Permission synchronization")
    class PermissionSynchronization {

        @Test
        @DisplayName("should create auto-policy with AUTO_POLICY_FOR_PERM_ prefix for new permission")
        void shouldCreateAutoPolicyForNewPermission() {
            // given
            Permission permission = mock(Permission.class);
            when(permission.getName()).thenReturn("CREATE_ORDER");
            when(permission.getFriendlyName()).thenReturn("Create Order");

            ManagedResource resource = mock(ManagedResource.class);
            when(resource.getResourceType()).thenReturn(ManagedResource.ResourceType.URL);
            when(resource.getResourceIdentifier()).thenReturn("/api/orders");
            when(resource.getHttpMethod()).thenReturn(ManagedResource.HttpMethod.POST);
            when(permission.getManagedResource()).thenReturn(resource);

            when(policyRepository.findByName("AUTO_POLICY_FOR_PERM_CREATE_ORDER"))
                    .thenReturn(Optional.empty());

            Policy savedPolicy = createPolicyEntity(100L, "AUTO_POLICY_FOR_PERM_CREATE_ORDER");
            when(policyRepository.save(any(Policy.class))).thenReturn(savedPolicy);
            when(permissionRepository.findAllByNameIn(anySet())).thenReturn(Collections.emptyList());

            // when
            policyService.synchronizePolicyForPermission(permission);

            // then
            verify(policyRepository).save(any(Policy.class));
        }

        @Test
        @DisplayName("should update existing auto-policy when permission already has one")
        void shouldUpdateExistingAutoPolicy() {
            // given
            Permission permission = mock(Permission.class);
            when(permission.getName()).thenReturn("UPDATE_ORDER");
            when(permission.getFriendlyName()).thenReturn("Update Order");

            ManagedResource resource = mock(ManagedResource.class);
            when(resource.getResourceType()).thenReturn(ManagedResource.ResourceType.URL);
            when(resource.getResourceIdentifier()).thenReturn("/api/orders");
            when(resource.getHttpMethod()).thenReturn(ManagedResource.HttpMethod.PUT);
            when(permission.getManagedResource()).thenReturn(resource);

            Policy existingPolicy = createPolicyEntityWithCollections(200L, "AUTO_POLICY_FOR_PERM_UPDATE_ORDER");
            when(policyRepository.findByName("AUTO_POLICY_FOR_PERM_UPDATE_ORDER"))
                    .thenReturn(Optional.of(existingPolicy));
            when(policyRepository.findByIdWithDetails(200L)).thenReturn(Optional.of(existingPolicy));
            when(policyRepository.save(any(Policy.class))).thenReturn(existingPolicy);
            when(permissionRepository.findAllByNameIn(anySet())).thenReturn(Collections.emptyList());

            // when
            policyService.synchronizePolicyForPermission(permission);

            // then
            verify(policyRepository).findByIdWithDetails(200L);
            verify(policyRepository).save(any(Policy.class));
        }

        @Test
        @DisplayName("should skip sync when permission has no linked resource")
        void shouldSkipWhenNoLinkedResource() {
            // given
            Permission permission = mock(Permission.class);
            when(permission.getName()).thenReturn("ORPHAN_PERM");
            when(permission.getManagedResource()).thenReturn(null);

            // when
            policyService.synchronizePolicyForPermission(permission);

            // then
            verify(policyRepository, never()).save(any(Policy.class));
            verify(policyRepository, never()).findByName(anyString());
        }
    }

    @Nested
    @DisplayName("DTO to entity mapping")
    class DtoToEntityMapping {

        @Test
        @DisplayName("should map targets from DTO to entity correctly")
        void shouldMapTargetsCorrectly() {
            // given
            PolicyDto dto = PolicyDto.builder()
                    .name("target-mapping-test")
                    .description("Test targets")
                    .effect(Policy.Effect.ALLOW)
                    .priority(100)
                    .targets(List.of(
                            new TargetDto("URL", "/api/users", "GET"),
                            new TargetDto("URL", "/api/admin", "ALL")
                    ))
                    .rules(new ArrayList<>())
                    .build();

            ArgumentCaptor<Policy> captor = ArgumentCaptor.forClass(Policy.class);
            Policy savedPolicy = createPolicyEntity(5L, "target-mapping-test");
            when(policyRepository.save(captor.capture())).thenReturn(savedPolicy);
            when(permissionRepository.findAllByNameIn(anySet())).thenReturn(Collections.emptyList());

            // when
            policyService.createPolicy(dto);

            // then
            Policy captured = captor.getValue();
            assertThat(captured.getTargets()).hasSize(2);

            // "ALL" httpMethod should be mapped to null
            boolean hasNullMethod = captured.getTargets().stream()
                    .anyMatch(t -> t.getHttpMethod() == null);
            assertThat(hasNullMethod).isTrue();
        }

        @Test
        @DisplayName("should map rules and conditions from DTO to entity")
        void shouldMapRulesAndConditions() {
            // given
            PolicyDto dto = PolicyDto.builder()
                    .name("rule-mapping-test")
                    .description("Test rules")
                    .effect(Policy.Effect.DENY)
                    .priority(200)
                    .targets(new ArrayList<>())
                    .rules(List.of(new RuleDto(
                            "Test rule",
                            List.of(new ConditionDto("hasAuthority('ADMIN')", PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE))
                    )))
                    .build();

            ArgumentCaptor<Policy> captor = ArgumentCaptor.forClass(Policy.class);
            Policy savedPolicy = createPolicyWithCondition(6L, "rule-mapping-test", "hasAuthority('ADMIN')");
            when(policyRepository.save(captor.capture())).thenReturn(savedPolicy);

            Permission perm = mock(Permission.class);
            when(perm.getId()).thenReturn(50L);
            when(permissionRepository.findAllByNameIn(Set.of("ADMIN"))).thenReturn(List.of(perm));

            // when
            policyService.createPolicy(dto);

            // then
            Policy captured = captor.getValue();
            assertThat(captured.getRules()).hasSize(1);
            PolicyRule rule = captured.getRules().iterator().next();
            assertThat(rule.getDescription()).isEqualTo("Test rule");
            assertThat(rule.getConditions()).hasSize(1);
            PolicyCondition condition = rule.getConditions().iterator().next();
            assertThat(condition.getExpression()).isEqualTo("hasAuthority('ADMIN')");
            assertThat(condition.getAuthorizationPhase()).isEqualTo(PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE);
        }
    }

    @Nested
    @DisplayName("Query operations")
    class QueryOperations {

        @Test
        @DisplayName("should return all policies with details")
        void shouldReturnAllPolicies() {
            // given
            List<Policy> expected = List.of(
                    createPolicyEntity(1L, "policy-1"),
                    createPolicyEntity(2L, "policy-2")
            );
            when(policyRepository.findAllWithDetails()).thenReturn(expected);

            // when
            List<Policy> result = policyService.getAllPolicies();

            // then
            assertThat(result).hasSize(2);
            verify(policyRepository).findAllWithDetails();
        }

        @Test
        @DisplayName("should find policy by ID with details")
        void shouldFindPolicyById() {
            // given
            Policy expected = createPolicyEntity(5L, "found-policy");
            when(policyRepository.findByIdWithDetails(5L)).thenReturn(Optional.of(expected));

            // when
            Policy result = policyService.findById(5L);

            // then
            assertThat(result.getName()).isEqualTo("found-policy");
        }

        @Test
        @DisplayName("should throw exception when policy not found by ID")
        void shouldThrowWhenNotFoundById() {
            // given
            when(policyRepository.findByIdWithDetails(404L)).thenReturn(Optional.empty());

            // when/then
            assertThatThrownBy(() -> policyService.findById(404L))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("404");
        }
    }

    // -- helper methods --

    private PolicyDto createSimplePolicyDto(String name, String description) {
        return PolicyDto.builder()
                .name(name)
                .description(description)
                .effect(Policy.Effect.ALLOW)
                .priority(100)
                .targets(new ArrayList<>())
                .rules(new ArrayList<>())
                .build();
    }

    private PolicyDto createPolicyDtoWithCondition(String name, String expression) {
        return PolicyDto.builder()
                .name(name)
                .description("Policy with condition")
                .effect(Policy.Effect.ALLOW)
                .priority(100)
                .targets(List.of(new TargetDto("URL", "/api/test", "GET")))
                .rules(List.of(new RuleDto(
                        "Rule with condition",
                        List.of(new ConditionDto(expression, PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE))
                )))
                .build();
    }

    private Policy createPolicyEntity(Long id, String name) {
        Policy policy = Policy.builder()
                .id(id)
                .name(name)
                .effect(Policy.Effect.ALLOW)
                .priority(100)
                .build();
        return policy;
    }

    private Policy createPolicyEntityWithCollections(Long id, String name) {
        Policy policy = Policy.builder()
                .id(id)
                .name(name)
                .effect(Policy.Effect.ALLOW)
                .priority(100)
                .targets(new HashSet<>())
                .rules(new HashSet<>())
                .build();
        return policy;
    }

    private Policy createPolicyWithCondition(Long id, String name, String expression) {
        Policy policy = Policy.builder()
                .id(id)
                .name(name)
                .effect(Policy.Effect.ALLOW)
                .priority(100)
                .targets(new HashSet<>())
                .rules(new HashSet<>())
                .build();

        PolicyRule rule = PolicyRule.builder()
                .policy(policy)
                .description("Test rule")
                .build();

        PolicyCondition condition = PolicyCondition.builder()
                .rule(rule)
                .expression(expression)
                .authorizationPhase(PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE)
                .build();

        rule.setConditions(Set.of(condition));
        policy.setRules(Set.of(rule));
        return policy;
    }
}
