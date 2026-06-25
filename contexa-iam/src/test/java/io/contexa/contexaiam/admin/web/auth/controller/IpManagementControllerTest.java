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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.domain.entity.IpAccessRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("IpManagementController")
class IpManagementControllerTest {

    @Mock
    private IpAccessRuleService ipAccessRuleService;


    @Mock
    private MessageSource messageSource;

    @Mock
    private CsvExportService csvExportService;

    private IpManagementController controller;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        SecurityContext context = new SecurityContextImpl();
        context.setAuthentication(new TestingAuthenticationToken("admin", "password"));
        SecurityContextHolder.setContext(context);

        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        controller = new IpManagementController(ipAccessRuleService, messageSource, csvExportService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Nested
    @DisplayName("list")
    class ListRules {

        @Test
        @DisplayName("should return index page with rules list")
        void listAll() throws Exception {
            PageImpl<IpAccessRule> page = new PageImpl<>(List.of(new IpAccessRule()));
            when(ipAccessRuleService.searchRules(eq(null), eq(null), any(Pageable.class))).thenReturn(page);
            when(ipAccessRuleService.normalizeRuleTypeFilter(null)).thenReturn(null);
            when(ipAccessRuleService.countAllowRules()).thenReturn(5L);
            when(ipAccessRuleService.countDenyRules()).thenReturn(2L);

            mockMvc.perform(get("/contexa/admin/ip-management"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("contexa/admin/ip-management"))
                    .andExpect(model().attribute("activePage", "ip-management"))
                    .andExpect(model().attributeExists("rules"))
                    .andExpect(model().attribute("allowCount", 5L))
                    .andExpect(model().attribute("denyCount", 2L))
                    .andExpect(model().attribute("totalCount", 7L));
        }

        @Test
        @DisplayName("should filter by rule type ALLOW without keyword")
        void filterByAllow() throws Exception {
            PageImpl<IpAccessRule> page = new PageImpl<>(Collections.emptyList());
            when(ipAccessRuleService.searchRules(eq("ALLOW"), eq(null), any(Pageable.class)))
                    .thenReturn(page);
            when(ipAccessRuleService.normalizeRuleTypeFilter("ALLOW"))
                    .thenReturn("ALLOW");

            mockMvc.perform(get("/contexa/admin/ip-management")
                            .param("type", "ALLOW"))
                    .andExpect(status().isOk())
                    .andExpect(model().attribute("currentType", "ALLOW"));
        }

        @Test
        @DisplayName("should search by keyword only")
        void searchByKeyword() throws Exception {
            PageImpl<IpAccessRule> page = new PageImpl<>(Collections.emptyList());
            when(ipAccessRuleService.searchRules(eq(null), eq("test"), any(Pageable.class)))
                    .thenReturn(page);
            when(ipAccessRuleService.normalizeRuleTypeFilter(null)).thenReturn(null);

            mockMvc.perform(get("/contexa/admin/ip-management")
                            .param("keyword", "test"))
                    .andExpect(status().isOk())
                    .andExpect(model().attribute("keyword", "test"));
        }

        @Test
        @DisplayName("should search by keyword and type DENY")
        void searchByKeywordAndDeny() throws Exception {
            PageImpl<IpAccessRule> page = new PageImpl<>(Collections.emptyList());
            when(ipAccessRuleService.searchRules(eq("DENY"), eq("192.168"), any(Pageable.class)))
                    .thenReturn(page);
            when(ipAccessRuleService.normalizeRuleTypeFilter("DENY"))
                    .thenReturn("DENY");

            mockMvc.perform(get("/contexa/admin/ip-management")
                            .param("type", "DENY")
                            .param("keyword", "192.168"))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("createRule")
    class CreateRule {

        @Test
        @DisplayName("should redirect and flash error when IP address format is invalid")
        void invalidIp() throws Exception {
            when(ipAccessRuleService.isValidIpOrCidr("invalid-ip")).thenReturn(false);

            mockMvc.perform(post("/contexa/admin/ip-management/create")
                            .param("ipAddress", "invalid-ip")
                            .param("ruleType", "ALLOW"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/ip-management"))
                    .andExpect(flash().attribute("errorMessage", "admin.ip.invalid.ip"));
        }

        @Test
        @DisplayName("should redirect and flash error when rule type is invalid")
        void invalidRuleType() throws Exception {
            when(ipAccessRuleService.isValidIpOrCidr("192.168.1.1")).thenReturn(true);

            mockMvc.perform(post("/contexa/admin/ip-management/create")
                            .param("ipAddress", "192.168.1.1")
                            .param("ruleType", "INVALID"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/ip-management"))
                    .andExpect(flash().attribute("errorMessage", "admin.ip.invalid.ip"));
        }

        @Test
        @DisplayName("should redirect and flash error when duplicate rule exists")
        void duplicateRule() throws Exception {
            when(ipAccessRuleService.isValidIpOrCidr("192.168.1.1")).thenReturn(true);
            when(ipAccessRuleService.existsByIpAndType("192.168.1.1", IpAccessRule.RuleType.DENY))
                    .thenReturn(true);

            mockMvc.perform(post("/contexa/admin/ip-management/create")
                            .param("ipAddress", "192.168.1.1")
                            .param("ruleType", "DENY"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/ip-management"))
                    .andExpect(flash().attribute("errorMessage", "admin.ip.duplicate"));
        }

        @Test
        @DisplayName("should create new rule and redirect with success message")
        void success() throws Exception {
            when(ipAccessRuleService.isValidIpOrCidr("192.168.1.0/24")).thenReturn(true);
            when(ipAccessRuleService.existsByIpAndType("192.168.1.0/24", IpAccessRule.RuleType.ALLOW))
                    .thenReturn(false);

            mockMvc.perform(post("/contexa/admin/ip-management/create")
                            .param("ipAddress", "192.168.1.0/24")
                            .param("ruleType", "ALLOW")
                            .param("description", "Office range")
                            .param("expiresAt", "2026-12-31T23:59:59"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/ip-management"))
                    .andExpect(flash().attribute("message", "admin.ip.created"));

            verify(ipAccessRuleService).createRule(
                    eq("192.168.1.0/24"),
                    eq(IpAccessRule.RuleType.ALLOW),
                    eq("Office range"),
                    eq("admin"),
                    eq(LocalDateTime.of(2026, 12, 31, 23, 59, 59))
            );
        }
    }

    @Nested
    @DisplayName("deleteRule")
    class DeleteRule {

        @Test
        @DisplayName("should redirect with success message when deleted successfully")
        void success() throws Exception {
            mockMvc.perform(post("/contexa/admin/ip-management/1/delete"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/ip-management"))
                    .andExpect(flash().attribute("message", "admin.ip.deleted"));

            verify(ipAccessRuleService).deleteRule(1L);
        }

        @Test
        @DisplayName("should redirect with error message when deletion fails")
        void failure() throws Exception {
            doThrow(new RuntimeException("Database error")).when(ipAccessRuleService).deleteRule(1L);

            mockMvc.perform(post("/contexa/admin/ip-management/1/delete"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/ip-management"))
                    .andExpect(flash().attribute("errorMessage", "msg.ip.delete.error"));
        }
    }

    @Nested
    @DisplayName("toggleRule")
    class ToggleRule {

        @Test
        @DisplayName("should redirect with success message when toggled successfully")
        void success() throws Exception {
            mockMvc.perform(post("/contexa/admin/ip-management/1/toggle"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/ip-management"))
                    .andExpect(flash().attribute("message", "admin.ip.toggled"));

            verify(ipAccessRuleService).toggleRule(1L);
        }

        @Test
        @DisplayName("should redirect with error message when toggle fails")
        void failure() throws Exception {
            doThrow(new RuntimeException("Rule not active")).when(ipAccessRuleService).toggleRule(1L);

            mockMvc.perform(post("/contexa/admin/ip-management/1/toggle"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/ip-management"))
                    .andExpect(flash().attribute("errorMessage", "msg.ip.toggle.error"));
        }
    }

    @Nested
    @DisplayName("export")
    class ExportRules {

        @Test
        @DisplayName("should invoke csvExportService")
        void success() throws Exception {
            mockMvc.perform(get("/contexa/admin/ip-management/export")
                            .param("type", "ALLOW"))
                    .andExpect(status().isOk());

            verify(csvExportService).export(any(), eq("ip-access-rules"), any(), any());
        }
    }
}
