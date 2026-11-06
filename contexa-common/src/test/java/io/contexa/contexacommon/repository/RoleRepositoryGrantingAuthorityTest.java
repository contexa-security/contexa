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
package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.Role;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class RoleRepositoryGrantingAuthorityTest {

    private static Role role(long id, String name) {
        return Role.builder().id(id).roleName(name).enabled(true).build();
    }

    private static RoleRepository repositoryHolding(Role... roles) {
        RoleRepository repository = mock(RoleRepository.class, CALLS_REAL_METHODS);
        doReturn(List.of(roles)).when(repository).findAll();
        return repository;
    }

    @Test
    @DisplayName("the roles that give an authority are the ones the ROLE_ rule names it for")
    void theRolesThatGiveAnAuthority() {
        RoleRepository repository = repositoryHolding(role(1, "O'Neil"), role(2, "O"), role(3, "ROLE_O'NEIL"),
                role(4, "ROLE_O'Neil"), role(5, "sales"), role(6, "ROLE_SALES"));

        assertThat(repository.findAllGrantingAuthority("ROLE_O'NEIL")).extracting(Role::getId).containsExactly(1L, 3L);
        assertThat(repository.findAllGrantingAuthority("ROLE_O'Neil")).extracting(Role::getId).containsExactly(4L);
        assertThat(repository.findAllGrantingAuthority("ROLE_SALES")).extracting(Role::getId).containsExactly(5L, 6L);
        assertThat(repository.findAllGrantingAuthority("ROLE_O")).extracting(Role::getId).containsExactly(2L);
    }

    @Test
    @DisplayName("a name that does not start with ROLE_ is the authority of no role, and nothing is read for it")
    void aNameWithoutThePrefixIsTheAuthorityOfNoRole() {
        RoleRepository repository = repositoryHolding(role(1, "O'Neil"), role(2, "O"));

        assertThat(repository.findAllGrantingAuthority("O'Neil")).isEmpty();
        assertThat(repository.findAllGrantingAuthority("O")).isEmpty();
        assertThat(repository.findAllGrantingAuthority("READ")).isEmpty();
        assertThat(repository.findAllGrantingAuthority(null)).isEmpty();
    }
}
