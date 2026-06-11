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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.PolicyTemplateRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.VisualPolicyDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.modelmapper.ModelMapper;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicyBuilderServiceImplTest {

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private PolicyTemplateRepository policyTemplateRepository;

    @Mock
    private PolicyService policyService;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private PolicyConflictAnalyzer policyConflictAnalyzer;

    private PolicyBuilderServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new PolicyBuilderServiceImpl(
                policyRepository, userRepository, permissionRepository,
                policyTemplateRepository, policyService, modelMapper, objectMapper,
                policyConflictAnalyzer);
    }

    @Nested
    @DisplayName("비주얼 컴포넌트에서 정책 변환")
    class VisualToPolicyTests {

        @Test
        @DisplayName("주체와 권한이 포함된 비주얼 컴포넌트에서 정책을 생성함")
        void shouldBuildPolicyFromVisualComponents() {
            Permission perm = mock(Permission.class);
            when(perm.getName()).thenReturn("URL_READ_USERS");
            ManagedResource mr = mock(ManagedResource.class);
            when(mr.getResourceType()).thenReturn(ManagedResource.ResourceType.URL);
            when(mr.getResourceIdentifier()).thenReturn("/api/users");
            when(mr.getHttpMethod()).thenReturn(null);
            when(perm.getManagedResource()).thenReturn(mr);

            when(permissionRepository.findAllById(Set.of(1L))).thenReturn(List.of(perm));

            Policy expectedPolicy = Policy.builder().name("visual-policy").effect(Policy.Effect.ALLOW).build();
            when(modelMapper.map(any(Policy.class), eq(PolicyDto.class))).thenReturn(new PolicyDto());
            when(policyService.createPolicy(any())).thenReturn(expectedPolicy);

            VisualPolicyDto dto = new VisualPolicyDto(
                    "visual-policy",
                    "Visual policy description",
                    Policy.Effect.ALLOW,
                    Set.of(new VisualPolicyDto.SubjectIdentifier(10L, "ROLE")),
                    Set.of(new VisualPolicyDto.PermissionIdentifier(1L)),
                    Set.of()
            );

            Policy result = service.buildPolicyFromVisualComponents(dto);

            assertThat(result).isNotNull();
            verify(policyService).createPolicy(any());
        }

        @Test
        @DisplayName("주체와 권한에 대한 SpEL expression이 포함된 규칙을 생성함")
        void shouldCreateRuleWithSpelExpressions() {
            Permission perm = mock(Permission.class);
            when(perm.getName()).thenReturn("URL_WRITE");
            when(perm.getManagedResource()).thenReturn(null);

            when(permissionRepository.findAllById(Set.of(5L))).thenReturn(List.of(perm));
            when(modelMapper.map(any(Policy.class), eq(PolicyDto.class))).thenReturn(new PolicyDto());
            when(policyService.createPolicy(any())).thenAnswer(inv -> {
                PolicyDto dto = inv.getArgument(0);
                return Policy.builder().name("test").effect(Policy.Effect.ALLOW).build();
            });

            VisualPolicyDto dto = new VisualPolicyDto(
                    "test-policy", "desc", Policy.Effect.ALLOW,
                    Set.of(new VisualPolicyDto.SubjectIdentifier(1L, "USER")),
                    Set.of(new VisualPolicyDto.PermissionIdentifier(5L)),
                    Set.of()
            );

            service.buildPolicyFromVisualComponents(dto);

            verify(policyService).createPolicy(any());
        }
    }

    @Nested
    @DisplayName("충돌 감지 위임 검증")
    class ConflictDetectionTests {

        @Test
        @DisplayName("detectConflicts 호출 시 PolicyConflictAnalyzer에 위임함")
        void shouldDelegateToAnalyzer() {
            Policy newPolicy = Policy.builder()
                    .id(2L).name("deny-policy").effect(Policy.Effect.DENY).build();
            newPolicy.setTargets(Set.of(PolicyTarget.builder()
                    .targetType("URL").targetIdentifier("/api/users").build()));

            service.detectConflicts(newPolicy);

            verify(policyConflictAnalyzer).analyze(newPolicy);
        }
    }
}
