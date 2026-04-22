package io.contexa.contexaiam.admin.web.menu.controller;

import io.contexa.contexacommon.entity.AdminMenu;
import io.contexa.contexacommon.entity.AdminMenuRole;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuManagementService;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
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
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("AdminMenuController contract")
class AdminMenuControllerTest {

    @Mock
    private AdminMenuService adminMenuService;

    @Mock
    private RoleRepository roleRepository;

    private AdminMenuController controller;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        AdminMenuManagementService adminMenuManagementService =
                new AdminMenuManagementService(adminMenuService, roleRepository);
        controller = new AdminMenuController(adminMenuManagementService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Nested
    @DisplayName("page")
    class Page {

        @Test
        @DisplayName("keeps existing view model names and parent-child sorting")
        void menuManagement() throws Exception {
            AdminMenu parent = menu(1L, "Parent", null, null, 2, true);
            AdminMenu child = menu(2L, "Child", "/child", 1L, 1, true);
            AdminMenu otherParent = menu(3L, "Other", "/other", null, 1, false);
            when(adminMenuService.getAllMenus()).thenReturn(List.of(parent, child, otherParent));
            when(roleRepository.findAll()).thenReturn(List.of(Role.builder().id(10L).roleName("ADMIN").build()));

            MvcResult result = mockMvc.perform(get("/admin/menu-management"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("admin/menu-management"))
                    .andExpect(model().attribute("activePage", "menu-management"))
                    .andReturn();

            List<?> menus = asList(result.getModelAndView().getModel().get("menus"));
            Set<Object> parentIds = asObjectSet(result.getModelAndView().getModel().get("parentIds"));
            List<?> allRoles = asList(result.getModelAndView().getModel().get("allRoles"));

            assertThat(menus).extracting(menu -> property(menu, "id")).containsExactly(3L, 1L, 2L);
            assertThat(parentIds).containsExactly(1L);
            assertThat(allRoles).extracting(role -> property(role, "roleName")).containsExactly("ADMIN");
        }

        @Test
        @DisplayName("direct method keeps model contract")
        void menuManagementDirect() {
            AdminMenu parent = menu(1L, "Parent", null, null, 1, true);
            AdminMenu child = menu(2L, "Child", "/child", 1L, 1, true);
            when(adminMenuService.getAllMenus()).thenReturn(List.of(parent, child));
            when(roleRepository.findAll()).thenReturn(List.of(Role.builder().id(10L).roleName("ADMIN").build()));

            Model model = new ConcurrentModel();
            String viewName = controller.menuManagement(model);

            assertThat(viewName).isEqualTo("admin/menu-management");
            assertThat(model.getAttribute("activePage")).isEqualTo("menu-management");
            assertThat(asList(model.getAttribute("menus"))).hasSize(2);
            assertThat(asObjectSet(model.getAttribute("parentIds"))).containsExactly(1L);
            assertThat(asList(model.getAttribute("allRoles")))
                    .extracting(role -> property(role, "roleName"))
                    .containsExactly("ADMIN");
        }

        @Test
        @DisplayName("does not drop orphan or nested menus from the page model")
        void menuManagementKeepsOrphanAndNestedMenus() {
            AdminMenu parent = menu(1L, "Parent", null, null, 2, true);
            AdminMenu child = menu(2L, "Child", "/child", 1L, 1, true);
            AdminMenu grandChild = menu(3L, "GrandChild", "/grand", 2L, 1, true);
            AdminMenu orphan = menu(4L, "Orphan", "/orphan", 999L, 3, true);
            when(adminMenuService.getAllMenus()).thenReturn(List.of(parent, child, grandChild, orphan));
            when(roleRepository.findAll()).thenReturn(List.of());

            Model model = new ConcurrentModel();
            String viewName = controller.menuManagement(model);

            assertThat(viewName).isEqualTo("admin/menu-management");
            assertThat(asList(model.getAttribute("menus")))
                    .extracting(menu -> property(menu, "id"))
                    .containsExactly(1L, 2L, 3L, 4L);
            assertThat(asObjectSet(model.getAttribute("parentIds")))
                    .containsExactlyInAnyOrder(1L, 2L, 999L);
        }
    }

    @Nested
    @DisplayName("commands")
    class Commands {

        @Test
        @DisplayName("toggle keeps success JSON")
        void toggle() throws Exception {
            mockMvc.perform(post("/admin/menu-management/api/toggle/1"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true));

            verify(adminMenuService).toggleEnabled(1L);
        }

        @Test
        @DisplayName("role update keeps request and response contract")
        void updateRoles() throws Exception {
            mockMvc.perform(post("/admin/menu-management/api/roles/1")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"roles\":[\"ADMIN\",\"AUDITOR\"]}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true));

            ArgumentCaptor<Set<String>> captor = ArgumentCaptor.forClass(Set.class);
            verify(adminMenuService).updateMenuRoles(eq(1L), captor.capture());
            assertThat(captor.getValue()).containsExactlyInAnyOrder("ADMIN", "AUDITOR");
        }

        @Test
        @DisplayName("order update keeps array request contract")
        void updateOrder() throws Exception {
            mockMvc.perform(post("/admin/menu-management/api/order")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    [{"id":1,"order":3},{"id":2,"order":"4"}]
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true));

            verify(adminMenuService).updateMenuOrder(1L, 3);
            verify(adminMenuService).updateMenuOrder(2L, 4);
        }

        @Test
        @DisplayName("order update rejects invalid numeric fields without partial updates")
        void updateOrderInvalidNumber() throws Exception {
            mockMvc.perform(post("/admin/menu-management/api/order")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    [{"id":1,"order":3},{"id":2,"order":"bad"}]
                                    """))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.error").value("order must be a number"));

            verify(adminMenuService, never()).updateMenuOrder(any(), any(Integer.class));
        }

        @Test
        @DisplayName("create keeps string request contract and id response")
        void createMenu() throws Exception {
            when(adminMenuService.saveMenu(any())).thenAnswer(invocation -> {
                AdminMenu menu = invocation.getArgument(0);
                menu.setId(99L);
                return menu;
            });

            mockMvc.perform(post("/admin/menu-management/api/create")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "name":"Custom",
                                      "url":"/admin/custom",
                                      "icon":"fas fa-star",
                                      "dataPage":"custom",
                                      "menuType":"CORE",
                                      "parentId":"1",
                                      "menuOrder":"7",
                                      "enabled":"false"
                                    }
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.id").value(99));

            ArgumentCaptor<AdminMenu> captor = ArgumentCaptor.forClass(AdminMenu.class);
            verify(adminMenuService).saveMenu(captor.capture());
            AdminMenu saved = captor.getValue();
            assertThat(saved.getName()).isEqualTo("Custom");
            assertThat(saved.getUrl()).isEqualTo("/admin/custom");
            assertThat(saved.getIcon()).isEqualTo("fas fa-star");
            assertThat(saved.getDataPage()).isEqualTo("custom");
            assertThat(saved.getMenuType()).isEqualTo("CORE");
            assertThat(saved.getParentId()).isEqualTo(1L);
            assertThat(saved.getMenuOrder()).isEqualTo(7);
            assertThat(saved.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("create rejects invalid numeric fields without saving")
        void createMenuInvalidNumber() throws Exception {
            mockMvc.perform(post("/admin/menu-management/api/create")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "name":"Custom",
                                      "parentId":"not-a-parent",
                                      "menuOrder":"7"
                                    }
                                    """))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.error").value("parentId must be a number"));

            verify(adminMenuService, never()).saveMenu(any());
        }

        @Test
        @DisplayName("update keeps partial string request contract")
        void updateMenu() throws Exception {
            AdminMenu menu = menu(1L, "Old", "/old", 9L, 1, true);
            when(adminMenuService.getMenuById(1L)).thenReturn(Optional.of(menu));

            mockMvc.perform(put("/admin/menu-management/api/1")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "name":"Updated",
                                      "url":"/updated",
                                      "icon":"fas fa-star",
                                      "dataPage":"updated",
                                      "menuType":"SAAS",
                                      "parentId":"",
                                      "menuOrder":"8",
                                      "enabled":"false"
                                    }
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true));

            verify(adminMenuService).saveMenu(menu);
            assertThat(menu.getName()).isEqualTo("Updated");
            assertThat(menu.getUrl()).isEqualTo("/updated");
            assertThat(menu.getIcon()).isEqualTo("fas fa-star");
            assertThat(menu.getDataPage()).isEqualTo("updated");
            assertThat(menu.getMenuType()).isEqualTo("SAAS");
            assertThat(menu.getParentId()).isNull();
            assertThat(menu.getMenuOrder()).isEqualTo(8);
            assertThat(menu.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("update rejects invalid numeric fields without saving")
        void updateMenuInvalidNumber() throws Exception {
            AdminMenu menu = menu(1L, "Old", "/old", 9L, 1, true);
            when(adminMenuService.getMenuById(1L)).thenReturn(Optional.of(menu));

            mockMvc.perform(put("/admin/menu-management/api/1")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "menuOrder":"bad"
                                    }
                                    """))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.error").value("menuOrder must be a number"));

            verify(adminMenuService, never()).saveMenu(any());
        }

        @Test
        @DisplayName("update missing keeps existing bad request JSON")
        void updateMissing() throws Exception {
            when(adminMenuService.getMenuById(404L)).thenReturn(Optional.empty());

            mockMvc.perform(put("/admin/menu-management/api/404")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"name\":\"Missing\"}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.error").value("Menu not found"));
        }

        @Test
        @DisplayName("delete custom menu keeps success JSON")
        void deleteCustom() throws Exception {
            when(adminMenuService.getMenuById(1L)).thenReturn(Optional.of(menu(1L, "Custom", "/custom", null, 1, true)));

            mockMvc.perform(delete("/admin/menu-management/api/1"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true));

            verify(adminMenuService).deleteMenu(1L);
        }

        @Test
        @DisplayName("delete system menu keeps existing bad request JSON")
        void deleteSystem() throws Exception {
            when(adminMenuService.getMenuById(1L)).thenReturn(Optional.of(menu(1L, "menu.dashboard", "/admin/dashboard", null, 1, true)));

            mockMvc.perform(delete("/admin/menu-management/api/1"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.error").value("System menu cannot be deleted"));

            verify(adminMenuService, never()).deleteMenu(1L);
        }

        @Test
        @DisplayName("delete missing keeps 404")
        void deleteMissing() throws Exception {
            when(adminMenuService.getMenuById(404L)).thenReturn(Optional.empty());

            mockMvc.perform(delete("/admin/menu-management/api/404"))
                    .andExpect(status().isNotFound());
        }
    }

    @Nested
    @DisplayName("query")
    class Query {

        @Test
        @DisplayName("getMenu keeps existing JSON fields")
        void getMenu() throws Exception {
            AdminMenu menu = menu(1L, "Custom", "/custom", 7L, 5, true);
            menu.setIcon("fas fa-star");
            menu.setMenuType("SAAS");
            menu.setDataPage("custom");
            menu.getRoles().clear();
            menu.addRole("ADMIN");
            menu.addRole("AUDITOR");
            when(adminMenuService.getMenuById(1L)).thenReturn(Optional.of(menu));

            mockMvc.perform(get("/admin/menu-management/api/1"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(1))
                    .andExpect(jsonPath("$.name").value("Custom"))
                    .andExpect(jsonPath("$.url").value("/custom"))
                    .andExpect(jsonPath("$.icon").value("fas fa-star"))
                    .andExpect(jsonPath("$.parentId").value(7))
                    .andExpect(jsonPath("$.menuOrder").value(5))
                    .andExpect(jsonPath("$.menuType").value("SAAS"))
                    .andExpect(jsonPath("$.dataPage").value("custom"))
                    .andExpect(jsonPath("$.enabled").value(true))
                    .andExpect(jsonPath("$.roles[*]", containsInAnyOrder("ADMIN", "AUDITOR")));
        }

        @Test
        @DisplayName("getMenu missing keeps 404")
        void getMenuMissing() throws Exception {
            when(adminMenuService.getMenuById(404L)).thenReturn(Optional.empty());

            mockMvc.perform(get("/admin/menu-management/api/404"))
                    .andExpect(status().isNotFound());
        }
    }

    @SuppressWarnings("unchecked")
    private List<?> asList(Object value) {
        return (List<?>) value;
    }

    @SuppressWarnings("unchecked")
    private Set<Object> asObjectSet(Object value) {
        return (Set<Object>) value;
    }

    private Object property(Object bean, String property) {
        return new BeanWrapperImpl(bean).getPropertyValue(property);
    }

    private AdminMenu menu(Long id, String name, String url, Long parentId, int order, boolean enabled) {
        AdminMenu menu = AdminMenu.builder()
                .id(id)
                .name(name)
                .url(url)
                .parentId(parentId)
                .menuOrder(order)
                .menuType("CORE")
                .dataPage("data-" + id)
                .enabled(enabled)
                .build();
        AdminMenuRole role = AdminMenuRole.builder()
                .menu(menu)
                .roleName("ADMIN")
                .build();
        if (id != null && id == 1L) {
            menu.getRoles().add(role);
        }
        return menu;
    }
}
