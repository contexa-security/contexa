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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.admin.web.auth.service.UnderOwnBlockException;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("BlacklistController")
class BlacklistControllerTest {

    @Mock
    private BlockedUserService blockedUserService;

    @Mock
    private MessageSource messageSource;

    @InjectMocks
    private BlacklistController controller;

    @BeforeEach
    void setUpSecurityContext() {
        SecurityContext context = new SecurityContextImpl();
        context.setAuthentication(new TestingAuthenticationToken("admin", "password"));
        SecurityContextHolder.setContext(context);
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> {
                    String key = inv.getArgument(0);
                    Object[] args = inv.getArgument(1);
                    if (args != null && args.length > 0) {
                        return key + " " + Arrays.stream(args)
                                .map(String::valueOf).collect(Collectors.joining(" "));
                    }
                    return key;
                });
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("listBlockedUsers")
    class ListBlockedUsers {

        @Test
        @DisplayName("should return all block history for null filter")
        void nullFilter() {
            Model model = new ConcurrentModel();
            List<BlockedUser> all = List.of(BlockedUser.builder().id(1L).build());
            when(blockedUserService.findBlockedUsers("all", null)).thenReturn(all);

            String view = controller.listBlockedUsers("all", null, model);

            assertThat(view).isEqualTo("contexa/admin/blacklist");
            assertThat(model.getAttribute("blockedUsers")).isEqualTo(all);
            assertThat(model.getAttribute("currentFilter")).isEqualTo("all");
        }

        @Test
        @DisplayName("should return blocked users for 'blocked' filter")
        void blockedFilter() {
            Model model = new ConcurrentModel();
            List<BlockedUser> blocked = List.of(BlockedUser.builder().id(2L).build());
            when(blockedUserService.findBlockedUsers("blocked", null)).thenReturn(blocked);

            String view = controller.listBlockedUsers("blocked", null, model);

            assertThat(view).isEqualTo("contexa/admin/blacklist");
            assertThat(model.getAttribute("blockedUsers")).isEqualTo(blocked);
            assertThat(model.getAttribute("currentFilter")).isEqualTo("blocked");
        }

        @Test
        @DisplayName("should return unblock requested users for 'unblock_requested' filter")
        void unblockRequestedFilter() {
            Model model = new ConcurrentModel();
            List<BlockedUser> requested = List.of(BlockedUser.builder().id(3L).build());
            when(blockedUserService.findBlockedUsers("unblock_requested", null)).thenReturn(requested);

            String view = controller.listBlockedUsers("unblock_requested", null, model);

            assertThat(view).isEqualTo("contexa/admin/blacklist");
            assertThat(model.getAttribute("blockedUsers")).isEqualTo(requested);
        }

        @Test
        @DisplayName("should filter resolved users from all history")
        void resolvedFilter() {
            Model model = new ConcurrentModel();
            BlockedUser resolved = BlockedUser.builder().id(4L).status(BlockedUserStatus.RESOLVED).build();
            when(blockedUserService.findBlockedUsers("resolved", null)).thenReturn(List.of(resolved));

            String view = controller.listBlockedUsers("resolved", null, model);

            assertThat(view).isEqualTo("contexa/admin/blacklist");
            @SuppressWarnings("unchecked")
            List<BlockedUser> result = (List<BlockedUser>) model.getAttribute("blockedUsers");
            assertThat(result).hasSize(1);
            assertThat(result.get(0).getId()).isEqualTo(4L);
        }

        @Test
        @DisplayName("should filter timeout_responded users from all history")
        void timeoutRespondedFilter() {
            Model model = new ConcurrentModel();
            BlockedUser timeout = BlockedUser.builder().id(6L).status(BlockedUserStatus.TIMEOUT_RESPONDED).build();
            when(blockedUserService.findBlockedUsers("timeout_responded", null)).thenReturn(List.of(timeout));

            String view = controller.listBlockedUsers("timeout_responded", null, model);

            assertThat(view).isEqualTo("contexa/admin/blacklist");
            @SuppressWarnings("unchecked")
            List<BlockedUser> result = (List<BlockedUser>) model.getAttribute("blockedUsers");
            assertThat(result).hasSize(1);
            assertThat(result.get(0).getId()).isEqualTo(6L);
        }
    }

    @Nested
    @DisplayName("getBlockDetail")
    class GetBlockDetail {

        @Test
        @DisplayName("should return detail view when block record exists")
        void success() {
            Model model = new ConcurrentModel();
            RedirectAttributes ra = new RedirectAttributesModelMap();
            BlockedUser blocked = BlockedUser.builder().id(1L).userId("user1").build();
            when(blockedUserService.getBlockDetail(1L)).thenReturn(Optional.of(blocked));

            String view = controller.getBlockDetail(1L, model, ra);

            assertThat(view).isEqualTo("contexa/admin/blacklist-detail");
            assertThat(model.getAttribute("blocked")).isEqualTo(blocked);
        }

        @Test
        @DisplayName("should redirect with error when block record not found")
        void notFound() {
            Model model = new ConcurrentModel();
            RedirectAttributes ra = new RedirectAttributesModelMap();
            when(blockedUserService.getBlockDetail(999L)).thenReturn(Optional.empty());

            String view = controller.getBlockDetail(999L, model, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/blacklist");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("999");
        }
    }

    @Nested
    @DisplayName("resolveBlock")
    class ResolveBlock {

        @Test
        @DisplayName("should redirect to blacklist on success")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();

            String view = controller.resolveBlock(1L, "UNBLOCK", "Test reason", ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/blacklist");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("resolved");
            verify(blockedUserService).resolveBlockById(eq(1L), eq("admin"), eq("UNBLOCK"), eq("Test reason"));
        }

        @Test
        @DisplayName("should redirect to detail page on error")
        void error() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new IllegalArgumentException("Not found"))
                    .when(blockedUserService).resolveBlockById(anyLong(), anyString(), anyString(), anyString());

            String view = controller.resolveBlock(1L, "UNBLOCK", "reason", ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/blacklist/1");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Not found");
        }

        @Test
        @DisplayName("should redirect to detail page on already resolved error")
        void alreadyResolved() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new IllegalStateException("Already resolved"))
                    .when(blockedUserService).resolveBlockById(anyLong(), anyString(), anyString(), anyString());

            String view = controller.resolveBlock(1L, "UNBLOCK", "reason", ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/blacklist/1");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Already resolved");
        }
    }

    @Nested
    @DisplayName("deleteBlockRecord")
    class DeleteBlockRecord {

        @Test
        @DisplayName("should redirect with success message on delete")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();

            String view = controller.deleteBlockRecord(1L, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/blacklist");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("deleted");
            verify(blockedUserService).deleteBlockRecord(1L, "admin");
        }

        @Test
        @DisplayName("should redirect with error message on failure")
        void error() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new RuntimeException("Cannot delete active block"))
                    .when(blockedUserService).deleteBlockRecord(1L, "admin");

            String view = controller.deleteBlockRecord(1L, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/blacklist");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Cannot delete active block");
        }

        @Test
        @DisplayName("an own record refused says why, as it is")
        void ownRecordRefused() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new AccessDeniedException("Another administrator lifts it"))
                    .when(blockedUserService).deleteBlockRecord(1L, "admin");

            assertThat(controller.deleteBlockRecord(1L, ra)).isEqualTo("redirect:/contexa/admin/blacklist");
            assertThat(ra.getFlashAttributes().get("errorMessage")).isEqualTo("Another administrator lifts it");
        }
    }

    @Nested
    @DisplayName("a session and its own block")
    class OwnRelease {

        @Test
        @DisplayName("a refused own release goes back to the record and says why, as it is")
        void aRefusedRelease() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new AccessDeniedException("Another administrator lifts it"))
                    .when(blockedUserService).resolveBlockById(anyLong(), anyString(), anyString(), anyString());

            String view = controller.resolveBlock(1L, "ALLOW", "it was me", ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/blacklist/1");
            assertThat(ra.getFlashAttributes().get("errorMessage")).isEqualTo("Another administrator lifts it");
        }

        @Test
        @DisplayName("a record already lifted, or deleted while in force, says so on the page without an ERROR")
        void theStateOfTheRecord() {
            Logger logger = (Logger) LoggerFactory.getLogger(BlacklistController.class);
            ListAppender<ILoggingEvent> lines = new ListAppender<>();
            lines.start();
            logger.addAppender(lines);
            try {
                RedirectAttributes resolved = new RedirectAttributesModelMap();
                doThrow(new IllegalStateException("Already resolved: id=1"))
                        .when(blockedUserService).resolveBlockById(1L, "admin", "ALLOW", "again");
                assertThat(controller.resolveBlock(1L, "ALLOW", "again", resolved))
                        .isEqualTo("redirect:/contexa/admin/blacklist/1");
                assertThat(resolved.getFlashAttributes().get("errorMessage")).isEqualTo("Already resolved: id=1");

                RedirectAttributes active = new RedirectAttributesModelMap();
                doThrow(new IllegalStateException("Cannot delete active block. Resolve first: id=1"))
                        .when(blockedUserService).deleteBlockRecord(1L, "admin");
                controller.deleteBlockRecord(1L, active);
                assertThat(active.getFlashAttributes().get("errorMessage"))
                        .isEqualTo("Cannot delete active block. Resolve first: id=1");

                assertThat(lines.list).noneMatch(line -> line.getLevel() == Level.ERROR);
            } finally {
                logger.detachAppender(lines);
            }
        }

        @Test
        @DisplayName("a session under its own BLOCK is not sent back to a page: the refusal goes on to its 403")
        void aSessionUnderItsOwnBlock() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            UnderOwnBlockException refused = new UnderOwnBlockException("It only reads");
            doThrow(refused).when(blockedUserService).resolveBlockById(anyLong(), anyString(), anyString(), anyString());
            doThrow(refused).when(blockedUserService).deleteBlockRecord(anyLong(), anyString());
            doThrow(refused).when(blockedUserService).releaseChallenge(anyString(), anyString(), anyString());

            assertThatThrownBy(() -> controller.resolveBlock(1L, "ALLOW", "checked", ra)).isSameAs(refused);
            assertThatThrownBy(() -> controller.deleteBlockRecord(1L, ra)).isSameAs(refused);
            assertThatThrownBy(() -> controller.releaseChallenge("alice", "checked", ra)).isSameAs(refused);
            assertThat(ra.getFlashAttributes()).isEmpty();
        }

        @Test
        @DisplayName("a refused CHALLENGE release says why, as it is")
        void aRefusedChallengeRelease() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new AccessDeniedException("Another administrator lifts it"))
                    .when(blockedUserService).releaseChallenge(anyString(), anyString(), anyString());

            String view = controller.releaseChallenge("console::admin", "it was me", ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/blacklist");
            assertThat(ra.getFlashAttributes().get("errorMessage")).isEqualTo("Another administrator lifts it");
        }

        @Test
        @DisplayName("the list tells a console session under its own BLOCK where to verify")
        void theListShowsTheWay() {
            when(blockedUserService.findBlockedUsers("all", null)).thenReturn(List.of());
            when(blockedUserService.ownBlockAwaitsVerification("admin")).thenReturn(true);
            Model model = new ConcurrentModel();

            controller.listBlockedUsers("all", null, model);

            assertThat(model.getAttribute("ownBlockAwaitsVerification")).isEqualTo(true);
        }
    }
}
