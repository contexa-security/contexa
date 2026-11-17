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
package io.contexa.contexaiam.admin.web.auth.dto;

import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.RoleOption;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/** K28: the default role drop-down names the roles by their descriptions, not by their codes. */
class SystemSettingsRoleOptionsTest {

    @Test
    void aRoleIsShownByItsDescriptionAlone() {
        assertThat(RoleOption.of("ROLE_USER", "일반 사용자 역할"))
                .isEqualTo(new RoleOption("ROLE_USER", "일반 사용자 역할"));
        assertThat(RoleOption.of("ROLE_AUDITOR", " ")).as("no description: the name is all there is")
                .isEqualTo(new RoleOption("ROLE_AUDITOR", "ROLE_AUDITOR"));
    }

    @Test
    void onlyRolesThatShareADescriptionNameTheirRole() {
        Map<String, String> roles = new LinkedHashMap<>();
        roles.put("ROLE_ADMIN", "시스템 전체 관리자 역할");
        roles.put("ROLE_OPS_A", "운영 역할");
        roles.put("ROLE_OPS_B", "운영 역할");
        roles.put("ROLE_USER", "일반 사용자 역할");

        List<RoleOption> options = RoleOption.of(roles);

        assertThat(options).extracting(RoleOption::value, RoleOption::label).containsExactly(
                tuple("ROLE_ADMIN", "시스템 전체 관리자 역할"),
                tuple("ROLE_OPS_A", "운영 역할 (ROLE_OPS_A)"),
                tuple("ROLE_OPS_B", "운영 역할 (ROLE_OPS_B)"),
                tuple("ROLE_USER", "일반 사용자 역할"));
    }

    @Test
    void theSeededRolesShowNoCode() {
        Map<String, String> roles = new LinkedHashMap<>();
        roles.put("ROLE_ADMIN", "시스템 전체 관리자 역할");
        roles.put("ROLE_DEVELOPER", "개발팀 역할 - 소프트웨어 개발 및 고객 데이터 관리");
        roles.put("ROLE_FINANCE", "재무팀 역할 - 회계 및 재무 데이터 관리");
        roles.put("ROLE_INFRA", "인프라팀 역할 - 시스템 운영 및 보안 관리");
        roles.put("ROLE_USER", "일반 사용자 역할");

        assertThat(RoleOption.of(roles)).extracting(RoleOption::label).noneMatch(label -> label.contains("ROLE_"));
    }
}
