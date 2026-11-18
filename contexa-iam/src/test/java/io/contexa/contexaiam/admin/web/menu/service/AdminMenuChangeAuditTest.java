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
package io.contexa.contexaiam.admin.web.menu.service;

import io.contexa.contexacommon.entity.AdminMenu;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuOrderRequest;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuRolesRequest;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** K75: a change of the menus is audited by its action, the menu's name and what changed. */
class AdminMenuChangeAuditTest {

    private final AdminMenuService menus = mock(AdminMenuService.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private AdminMenuManagementService service;

    @BeforeEach
    void setUp() {
        service = new AdminMenuManagementService(menus, mock(RoleRepository.class),
                I18nTestSupport.englishMessageSource());
        service.setCentralAuditFacade(audit);
    }

    @Test
    void switchingReorderingAndGivingRolesAreAudited() {
        AdminMenu menu = new AdminMenu();
        menu.setId(4L);
        menu.setName("menu.security.events");
        menu.setUrl("/contexa/admin/security-monitor");
        menu.setEnabled(false);
        when(menus.getMenuById(4L)).thenReturn(Optional.of(menu));

        service.toggleMenu(4L);
        service.updateRoles(4L, new AdminMenuRolesRequest(List.of("ROLE_AUDITOR", "ROLE_ADMIN")));
        service.updateOrder(List.of(new AdminMenuOrderRequest("4", "2"), new AdminMenuOrderRequest("5", "1")));
        service.toggleMenu(99L);

        ArgumentCaptor<AuditRecord> records = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit, times(3)).recordAsync(records.capture());
        assertThat(records.getAllValues()).extracting(AuditRecord::getEventCategory, AuditRecord::getAction,
                AuditRecord::getResourceIdentifier).containsExactly(
                tuple(AuditEventCategory.MENU_CHANGED, "MENU_SWITCHED", "menu.security.events"),
                tuple(AuditEventCategory.MENU_CHANGED, "MENU_ROLES_CHANGED", "menu.security.events"),
                tuple(AuditEventCategory.MENU_CHANGED, "MENU_REORDERED", ""));
        assertThat(records.getAllValues().get(0).getDetails()).containsEntry("enabled", false);
        assertThat(records.getAllValues().get(1).getDetails()).containsEntry("roles", List.of("ROLE_ADMIN",
                "ROLE_AUDITOR"));
    }
}
