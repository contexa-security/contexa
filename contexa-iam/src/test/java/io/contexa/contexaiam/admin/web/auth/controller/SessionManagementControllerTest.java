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

import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.domain.entity.ActiveSession;
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
import org.springframework.data.domain.Pageable;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

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
@DisplayName("SessionManagementController")
class SessionManagementControllerTest {

    @Mock
    private SessionManagementService sessionManagementService;


    @Mock
    private MessageSource messageSource;

    @Mock
    private CsvExportService csvExportService;

    private SessionManagementController controller;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        controller = new SessionManagementController(sessionManagementService, messageSource, csvExportService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Nested
    @DisplayName("list")
    class ListSessions {

        @Test
        @DisplayName("should return index page with active sessions list")
        void listAll() throws Exception {
            PageImpl<ActiveSession> page = new PageImpl<>(List.of(new ActiveSession()));
            when(sessionManagementService.searchActiveSessions(eq(null), any(Pageable.class))).thenReturn(page);
            when(sessionManagementService.getActiveSessionCount()).thenReturn(3L);

            mockMvc.perform(get("/contexa/admin/session-management"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("contexa/admin/session-management"))
                    .andExpect(model().attribute("activePage", "session-management"))
                    .andExpect(model().attributeExists("sessionPage"))
                    .andExpect(model().attribute("activeCount", 3L));
        }

        @Test
        @DisplayName("should search active sessions by keyword")
        void search() throws Exception {
            PageImpl<ActiveSession> page = new PageImpl<>(Collections.emptyList());
            when(sessionManagementService.searchActiveSessions(eq("test"), any(Pageable.class))).thenReturn(page);

            mockMvc.perform(get("/contexa/admin/session-management")
                            .param("keyword", "test"))
                    .andExpect(status().isOk())
                    .andExpect(model().attribute("keyword", "test"));
        }
    }

    @Nested
    @DisplayName("invalidateSession")
    class InvalidateSession {

        @Test
        @DisplayName("should redirect with success message when invalidated successfully")
        void success() throws Exception {
            mockMvc.perform(post("/contexa/admin/session-management/sess-123/invalidate"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/session-management"))
                    .andExpect(flash().attribute("message", "admin.session.invalidated"));

            verify(sessionManagementService).invalidateSession("sess-123");
        }

        @Test
        @DisplayName("should redirect with error message when invalidation fails")
        void failure() throws Exception {
            doThrow(new RuntimeException("Lock failed")).when(sessionManagementService).invalidateSession("sess-123");

            mockMvc.perform(post("/contexa/admin/session-management/sess-123/invalidate"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/session-management"))
                    .andExpect(flash().attribute("errorMessage", "msg.session.invalidate.error"));
        }
    }

    @Nested
    @DisplayName("invalidateAllForUser")
    class InvalidateAllForUser {

        @Test
        @DisplayName("should redirect with success message when invalidated successfully")
        void success() throws Exception {
            mockMvc.perform(post("/contexa/admin/session-management/user/user-1/invalidate-all"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/session-management"))
                    .andExpect(flash().attribute("message", "admin.session.all.invalidated"));

            verify(sessionManagementService).invalidateAllSessionsForUser("user-1");
        }

        @Test
        @DisplayName("should redirect with error message when invalidation fails")
        void failure() throws Exception {
            doThrow(new RuntimeException("Database error")).when(sessionManagementService).invalidateAllSessionsForUser("user-1");

            mockMvc.perform(post("/contexa/admin/session-management/user/user-1/invalidate-all"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/session-management"))
                    .andExpect(flash().attribute("errorMessage", "msg.session.invalidate.all.error"));
        }
    }

    @Nested
    @DisplayName("export")
    class ExportSessions {

        @Test
        @DisplayName("should invoke csvExportService")
        void success() throws Exception {
            mockMvc.perform(get("/contexa/admin/session-management/export"))
                    .andExpect(status().isOk());

            verify(csvExportService).export(any(), eq("active-sessions"), any(), any());
        }
    }
}
