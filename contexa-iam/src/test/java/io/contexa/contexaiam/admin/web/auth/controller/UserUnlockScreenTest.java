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

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** An administrator sees the release of a lock on a locked user's page, and on no other. */
class UserUnlockScreenTest {

    private final UserManagementService users = mock(UserManagementService.class);
    private final RoleService roles = mock(RoleService.class);
    private final GroupService groups = mock(GroupService.class);
    private MockMvc mvc;

    @BeforeEach
    void aConsole() {
        when(roles.getRolesWithoutExpression()).thenReturn(List.of());
        when(groups.getAllGroups()).thenReturn(List.of());
        ThymeleafViewResolver views = new ThymeleafViewResolver();
        views.setTemplateEngine(engine());
        views.setCharacterEncoding("UTF-8");
        mvc = MockMvcBuilders.standaloneSetup(new UserManagementController(users, roles, groups,
                        mock(PasswordPolicyService.class), messages()))
                .setViewResolvers(views)
                .build();
    }

    private String page(boolean locked) throws Exception {
        UserDto user = new UserDto();
        user.setId(5L);
        user.setUsername("alice");
        user.setAccountLocked(locked);
        when(users.findUser(5L)).thenReturn(Optional.of(user));
        return mvc.perform(get("/contexa/admin/users/5").locale(Locale.ENGLISH)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    @Test
    @DisplayName("a locked user's page offers the release and says what it leaves")
    void aLockedUser() throws Exception {
        assertThat(page(true)).contains("action=\"/contexa/admin/users/5/unlock\"", "unlockForm",
                "does not lift a limit on an address");
    }

    @Test
    @DisplayName("the page of a user under no lock does not")
    void aUserUnderNoLock() throws Exception {
        assertThat(page(false)).doesNotContain("/unlock", "unlockForm");
    }

    @Test
    @DisplayName("the release answers at its address and goes back to the user")
    void theAddress() throws Exception {
        when(users.unlockUser(5L)).thenReturn(true);

        mvc.perform(post("/contexa/admin/users/5/unlock")).andExpect(redirectedUrl("/contexa/admin/users/5"));
    }

    private static ResourceBundleMessageSource messages() {
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setFallbackToSystemLocale(false);
        return messages;
    }

    private static SpringTemplateEngine engine() {
        ClassLoaderTemplateResolver fragments = resolver("test-templates/", 1);
        fragments.setResolvablePatterns(Set.of("contexa/fragments/*"));
        ClassLoaderTemplateResolver templates = resolver("templates/", 2);
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolvers(Set.of(fragments, templates));
        engine.setTemplateEngineMessageSource(messages());
        return engine;
    }

    private static ClassLoaderTemplateResolver resolver(String prefix, int order) {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix(prefix);
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        resolver.setCheckExistence(true);
        resolver.setOrder(order);
        return resolver;
    }
}
