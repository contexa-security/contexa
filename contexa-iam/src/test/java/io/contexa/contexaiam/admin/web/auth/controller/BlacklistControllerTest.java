package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
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
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("BlacklistController")
class BlacklistControllerTest {

    @Mock
    private BlockedUserService blockedUserService;

    @InjectMocks
    private BlacklistController controller;

    @BeforeEach
    void setUpSecurityContext() {
        SecurityContext context = new SecurityContextImpl();
        context.setAuthentication(new TestingAuthenticationToken("admin", "password"));
        SecurityContextHolder.setContext(context);
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
            when(blockedUserService.getAllBlockHistory()).thenReturn(all);

            String view = controller.listBlockedUsers("all", model);

            assertThat(view).isEqualTo("admin/blacklist");
            assertThat(model.getAttribute("blockedUsers")).isEqualTo(all);
            assertThat(model.getAttribute("currentFilter")).isEqualTo("all");
        }

        @Test
        @DisplayName("should return blocked users for 'blocked' filter")
        void blockedFilter() {
            Model model = new ConcurrentModel();
            List<BlockedUser> blocked = List.of(BlockedUser.builder().id(2L).build());
            when(blockedUserService.getBlockedUsers()).thenReturn(blocked);

            String view = controller.listBlockedUsers("blocked", model);

            assertThat(view).isEqualTo("admin/blacklist");
            assertThat(model.getAttribute("blockedUsers")).isEqualTo(blocked);
            assertThat(model.getAttribute("currentFilter")).isEqualTo("blocked");
        }

        @Test
        @DisplayName("should return unblock requested users for 'unblock_requested' filter")
        void unblockRequestedFilter() {
            Model model = new ConcurrentModel();
            List<BlockedUser> requested = List.of(BlockedUser.builder().id(3L).build());
            when(blockedUserService.getUnblockRequested()).thenReturn(requested);

            String view = controller.listBlockedUsers("unblock_requested", model);

            assertThat(view).isEqualTo("admin/blacklist");
            assertThat(model.getAttribute("blockedUsers")).isEqualTo(requested);
        }

        @Test
        @DisplayName("should filter resolved users from all history")
        void resolvedFilter() {
            Model model = new ConcurrentModel();
            BlockedUser resolved = BlockedUser.builder().id(4L).status(BlockedUserStatus.RESOLVED).build();
            BlockedUser blocked = BlockedUser.builder().id(5L).status(BlockedUserStatus.BLOCKED).build();
            when(blockedUserService.getAllBlockHistory()).thenReturn(List.of(resolved, blocked));

            String view = controller.listBlockedUsers("resolved", model);

            assertThat(view).isEqualTo("admin/blacklist");
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
            BlockedUser blocked = BlockedUser.builder().id(7L).status(BlockedUserStatus.BLOCKED).build();
            when(blockedUserService.getAllBlockHistory()).thenReturn(List.of(timeout, blocked));

            String view = controller.listBlockedUsers("timeout_responded", model);

            assertThat(view).isEqualTo("admin/blacklist");
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

            assertThat(view).isEqualTo("admin/blacklist-detail");
            assertThat(model.getAttribute("blocked")).isEqualTo(blocked);
        }

        @Test
        @DisplayName("should redirect with error when block record not found")
        void notFound() {
            Model model = new ConcurrentModel();
            RedirectAttributes ra = new RedirectAttributesModelMap();
            when(blockedUserService.getBlockDetail(999L)).thenReturn(Optional.empty());

            String view = controller.getBlockDetail(999L, model, ra);

            assertThat(view).isEqualTo("redirect:/admin/blacklist");
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

            assertThat(view).isEqualTo("redirect:/admin/blacklist");
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

            assertThat(view).isEqualTo("redirect:/admin/blacklist/1");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Not found");
        }

        @Test
        @DisplayName("should redirect to detail page on already resolved error")
        void alreadyResolved() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new IllegalStateException("Already resolved"))
                    .when(blockedUserService).resolveBlockById(anyLong(), anyString(), anyString(), anyString());

            String view = controller.resolveBlock(1L, "UNBLOCK", "reason", ra);

            assertThat(view).isEqualTo("redirect:/admin/blacklist/1");
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

            assertThat(view).isEqualTo("redirect:/admin/blacklist");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("deleted");
            verify(blockedUserService).deleteBlockRecord(1L);
        }

        @Test
        @DisplayName("should redirect with error message on failure")
        void error() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new RuntimeException("Cannot delete active block"))
                    .when(blockedUserService).deleteBlockRecord(1L);

            String view = controller.deleteBlockRecord(1L, ra);

            assertThat(view).isEqualTo("redirect:/admin/blacklist");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Cannot delete active block");
        }
    }
}
