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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion;
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion.ChangeType;
import io.contexa.contexaiam.repository.PolicyVersionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.modelmapper.ModelMapper;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicyVersionServiceTest {

    @Mock private PolicyVersionRepository versionRepository;
    @Mock private ObjectMapper objectMapper;
    @Mock private ModelMapper modelMapper;

    private PolicyVersionService service;

    @BeforeEach
    void setUp() {
        service = new PolicyVersionService(versionRepository, objectMapper, modelMapper);
    }

    private Policy buildPolicy(Long id, String name) {
        return Policy.builder().id(id).name(name).effect(Policy.Effect.ALLOW).priority(100).build();
    }

    // ── 1. 버전 생성 ────────────────────────────────────────────

    @Nested
    @DisplayName("버전 생성")
    class CreateVersion {

        @Test
        @DisplayName("정책 생성 시 버전 번호 1로 스냅샷을 저장함")
        void createFirstVersion() throws JsonProcessingException {
            Policy policy = buildPolicy(10L, "test-policy");
            when(versionRepository.findMaxVersionNumber(10L)).thenReturn(0);
            when(modelMapper.map(policy, PolicyDto.class)).thenReturn(new PolicyDto());
            when(objectMapper.writeValueAsString(any(PolicyDto.class))).thenReturn("{\"name\":\"test\"}");
            when(versionRepository.save(any(PolicyVersion.class))).thenAnswer(inv -> inv.getArgument(0));

            PolicyVersion result = service.createVersion(policy, ChangeType.CREATED, "initial creation");

            assertThat(result.getPolicyId()).isEqualTo(10L);
            assertThat(result.getVersionNumber()).isEqualTo(1);
            assertThat(result.getChangeType()).isEqualTo(ChangeType.CREATED);
            assertThat(result.getChangeReason()).isEqualTo("initial creation");
            assertThat(result.getSnapshotJson()).isEqualTo("{\"name\":\"test\"}");
        }

        @Test
        @DisplayName("기존 버전이 있으면 다음 번호로 생성함")
        void createNextVersion() throws JsonProcessingException {
            Policy policy = buildPolicy(10L, "test-policy");
            when(versionRepository.findMaxVersionNumber(10L)).thenReturn(3);
            when(modelMapper.map(policy, PolicyDto.class)).thenReturn(new PolicyDto());
            when(objectMapper.writeValueAsString(any())).thenReturn("{}");
            when(versionRepository.save(any(PolicyVersion.class))).thenAnswer(inv -> inv.getArgument(0));

            PolicyVersion result = service.createVersion(policy, ChangeType.UPDATED, "updated");

            assertThat(result.getVersionNumber()).isEqualTo(4);
        }

        @Test
        @DisplayName("직렬화 실패 시 빈 JSON으로 저장함")
        void serializationFailureFallback() throws JsonProcessingException {
            Policy policy = buildPolicy(10L, "test-policy");
            when(versionRepository.findMaxVersionNumber(10L)).thenReturn(0);
            when(modelMapper.map(policy, PolicyDto.class)).thenReturn(new PolicyDto());
            when(objectMapper.writeValueAsString(any())).thenThrow(new JsonProcessingException("fail") {});
            when(versionRepository.save(any(PolicyVersion.class))).thenAnswer(inv -> inv.getArgument(0));

            PolicyVersion result = service.createVersion(policy, ChangeType.CREATED, null);

            assertThat(result.getSnapshotJson()).isEqualTo("{}");
        }

        @Test
        @DisplayName("changeReason이 null이어도 정상 생성됨")
        void nullReasonAllowed() throws JsonProcessingException {
            Policy policy = buildPolicy(10L, "test");
            when(versionRepository.findMaxVersionNumber(10L)).thenReturn(0);
            when(modelMapper.map(policy, PolicyDto.class)).thenReturn(new PolicyDto());
            when(objectMapper.writeValueAsString(any())).thenReturn("{}");
            when(versionRepository.save(any(PolicyVersion.class))).thenAnswer(inv -> inv.getArgument(0));

            PolicyVersion result = service.createVersion(policy, ChangeType.CREATED, null);

            assertThat(result.getChangeReason()).isNull();
            verify(versionRepository).save(any());
        }
    }

    // ── 2. 버전 이력 조회 ───────────────────────────────────────

    @Nested
    @DisplayName("버전 이력 조회")
    class GetVersions {

        @Test
        @DisplayName("정책 ID로 버전 이력을 내림차순 조회함")
        void getVersionsByPolicyId() {
            PolicyVersion v2 = PolicyVersion.builder().policyId(10L).versionNumber(2).build();
            PolicyVersion v1 = PolicyVersion.builder().policyId(10L).versionNumber(1).build();
            when(versionRepository.findByPolicyIdOrderByVersionNumberDesc(10L))
                    .thenReturn(List.of(v2, v1));

            List<PolicyVersion> result = service.getVersions(10L);

            assertThat(result).hasSize(2);
            assertThat(result.get(0).getVersionNumber()).isEqualTo(2);
            assertThat(result.get(1).getVersionNumber()).isEqualTo(1);
        }

        @Test
        @DisplayName("버전이 없으면 빈 목록을 반환함")
        void emptyVersions() {
            when(versionRepository.findByPolicyIdOrderByVersionNumberDesc(99L))
                    .thenReturn(List.of());

            List<PolicyVersion> result = service.getVersions(99L);

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("특정 버전 번호로 단건 조회함")
        void getSpecificVersion() {
            PolicyVersion v = PolicyVersion.builder().policyId(10L).versionNumber(2).build();
            when(versionRepository.findByPolicyIdAndVersionNumber(10L, 2))
                    .thenReturn(Optional.of(v));

            Optional<PolicyVersion> result = service.getVersion(10L, 2);

            assertThat(result).isPresent();
            assertThat(result.get().getVersionNumber()).isEqualTo(2);
        }
    }

    // ── 3. 스냅샷 역직렬화 ──────────────────────────────────────

    @Nested
    @DisplayName("스냅샷 역직렬화")
    class DeserializeSnapshot {

        @Test
        @DisplayName("유효한 JSON 스냅샷을 PolicyDto로 역직렬화함")
        void deserializeValid() throws JsonProcessingException {
            PolicyVersion version = PolicyVersion.builder()
                    .snapshotJson("{\"name\":\"test\"}").build();
            PolicyDto dto = new PolicyDto();
            dto.setName("test");
            when(objectMapper.readValue("{\"name\":\"test\"}", PolicyDto.class)).thenReturn(dto);

            Optional<PolicyDto> result = service.deserializeSnapshot(version);

            assertThat(result).isPresent();
            assertThat(result.get().getName()).isEqualTo("test");
        }

        @Test
        @DisplayName("잘못된 JSON이면 빈 Optional을 반환함")
        void deserializeInvalid() throws JsonProcessingException {
            PolicyVersion version = PolicyVersion.builder()
                    .id(1L).snapshotJson("invalid").build();
            when(objectMapper.readValue("invalid", PolicyDto.class))
                    .thenThrow(new JsonProcessingException("parse error") {});

            Optional<PolicyDto> result = service.deserializeSnapshot(version);

            assertThat(result).isEmpty();
        }
    }

    // ── 4. 버전 비교 ────────────────────────────────────────────

    @Nested
    @DisplayName("버전 비교")
    class CompareVersions {

        @Test
        @DisplayName("두 버전 간 변경된 필드를 비교함")
        @SuppressWarnings("unchecked")
        void compareDifferentVersions() throws JsonProcessingException {
            PolicyVersion v1 = PolicyVersion.builder()
                    .policyId(10L).versionNumber(1).snapshotJson("{\"name\":\"old\"}").build();
            PolicyVersion v2 = PolicyVersion.builder()
                    .policyId(10L).versionNumber(2).snapshotJson("{\"name\":\"new\"}").build();

            when(versionRepository.findByPolicyIdAndVersionNumber(10L, 1)).thenReturn(Optional.of(v1));
            when(versionRepository.findByPolicyIdAndVersionNumber(10L, 2)).thenReturn(Optional.of(v2));
            when(objectMapper.readValue(eq("{\"name\":\"old\"}"), eq(Map.class)))
                    .thenReturn(Map.of("name", "old", "priority", 100));
            when(objectMapper.readValue(eq("{\"name\":\"new\"}"), eq(Map.class)))
                    .thenReturn(Map.of("name", "new", "priority", 100));

            List<Map<String, String>> changes = service.compareVersions(10L, 1, 2);

            assertThat(changes).hasSize(1);
            assertThat(changes.get(0).get("field")).isEqualTo("name");
            assertThat(changes.get(0).get("before")).isEqualTo("old");
            assertThat(changes.get(0).get("after")).isEqualTo("new");
        }

        @Test
        @DisplayName("동일한 버전이면 변경사항이 없음")
        @SuppressWarnings("unchecked")
        void compareIdenticalVersions() throws JsonProcessingException {
            PolicyVersion v1 = PolicyVersion.builder()
                    .policyId(10L).versionNumber(1).snapshotJson("{}").build();
            PolicyVersion v2 = PolicyVersion.builder()
                    .policyId(10L).versionNumber(2).snapshotJson("{}").build();

            when(versionRepository.findByPolicyIdAndVersionNumber(10L, 1)).thenReturn(Optional.of(v1));
            when(versionRepository.findByPolicyIdAndVersionNumber(10L, 2)).thenReturn(Optional.of(v2));
            when(objectMapper.readValue(eq("{}"), eq(Map.class)))
                    .thenReturn(Map.of("name", "same"));

            List<Map<String, String>> changes = service.compareVersions(10L, 1, 2);

            assertThat(changes).isEmpty();
        }

        @Test
        @DisplayName("존재하지 않는 버전 비교 시 예외 발생")
        void compareNonExistentVersion() {
            when(versionRepository.findByPolicyIdAndVersionNumber(10L, 1)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.compareVersions(10L, 1, 2))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Version 1 not found");
        }

        @Test
        @DisplayName("필드가 추가되거나 제거된 경우도 감지함")
        @SuppressWarnings("unchecked")
        void compareWithAddedAndRemovedFields() throws JsonProcessingException {
            PolicyVersion v1 = PolicyVersion.builder()
                    .policyId(10L).versionNumber(1).snapshotJson("v1").build();
            PolicyVersion v2 = PolicyVersion.builder()
                    .policyId(10L).versionNumber(2).snapshotJson("v2").build();

            when(versionRepository.findByPolicyIdAndVersionNumber(10L, 1)).thenReturn(Optional.of(v1));
            when(versionRepository.findByPolicyIdAndVersionNumber(10L, 2)).thenReturn(Optional.of(v2));

            Map<String, Object> map1 = new java.util.HashMap<>();
            map1.put("name", "test");
            map1.put("oldField", "removed");
            Map<String, Object> map2 = new java.util.HashMap<>();
            map2.put("name", "test");
            map2.put("newField", "added");

            when(objectMapper.readValue(eq("v1"), eq(Map.class))).thenReturn(map1);
            when(objectMapper.readValue(eq("v2"), eq(Map.class))).thenReturn(map2);

            List<Map<String, String>> changes = service.compareVersions(10L, 1, 2);

            assertThat(changes).hasSize(2);
            assertThat(changes.stream().anyMatch(c ->
                    "oldField".equals(c.get("field")) && "removed".equals(c.get("before")) && "".equals(c.get("after"))
            )).isTrue();
            assertThat(changes.stream().anyMatch(c ->
                    "newField".equals(c.get("field")) && "".equals(c.get("before")) && "added".equals(c.get("after"))
            )).isTrue();
        }
    }
}
