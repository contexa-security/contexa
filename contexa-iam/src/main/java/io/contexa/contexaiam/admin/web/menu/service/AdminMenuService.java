package io.contexa.contexaiam.admin.web.menu.service;

import io.contexa.contexacommon.entity.AdminMenu;
import io.contexa.contexacommon.entity.AdminMenuRole;
import io.contexa.contexacommon.repository.AdminMenuRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class AdminMenuService {

    private final AdminMenuRepository menuRepository;
    private final AdminMenuQueryCache menuQueryCache;
    private final boolean enterpriseEnabled;
    private final boolean saasEnabled;

    public AdminMenuService(AdminMenuRepository menuRepository,
                            AdminMenuQueryCache menuQueryCache,
                            boolean enterpriseEnabled,
                            boolean saasEnabled) {
        this.menuRepository = menuRepository;
        this.menuQueryCache = menuQueryCache;
        this.enterpriseEnabled = enterpriseEnabled;
        this.saasEnabled = saasEnabled;
    }

    /**
     * Initialize default menus if the table is empty and backfill new enterprise/saas menus in existing deployments.
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public void initializeDefaultMenusIfEmpty() {
        if (menuRepository.count() == 0) {
            Long dashId = createMenu("menu.dashboard", "/admin/dashboard", svgHome(), null, 1, "CORE", "dashboard");
            Long policyId = createMenu("menu.nav.policy", null, svgShield(), null, 2, "CORE", "policy");
            Long accessId = createMenu("menu.nav.access", null, svgKey(), null, 3, "CORE", "access");
            Long iamId = createMenu("menu.nav.iam", null, svgPeople(), null, 4, "CORE", "iam");
            Long securityId = createMenu("menu.nav.security", null, svgEye(), null, 5, "CORE", "security");
            Long enterpriseId = createMenu("menu.nav.enterprise", null, svgBuilding(), null, 6, "ENTERPRISE", "enterprise");
            Long saasId = createMenu("menu.nav.saas", null, svgCloud(), null, 7, "SAAS", "saas");

            createMenu("menu.policy.center", "/admin/policy-center", "", policyId, 1, "CORE", "policy-center");
            createMenu("menu.access.center", "/admin/access-center", "", accessId, 1, "CORE", "access-center");
            createMenu("menu.iam.users", "/admin/users", "", iamId, 1, "CORE", "users");
            createMenu("menu.iam.groups", "/admin/groups", "", iamId, 2, "CORE", "groups");
            createMenu("menu.iam.roles", "/admin/roles", "", iamId, 3, "CORE", "roles");
            createMenu("menu.iam.permissions", "/admin/permissions", "", iamId, 4, "CORE", "permissions");
            createMenu("menu.iam.role.hierarchies", "/admin/role-hierarchies", "", iamId, 5, "CORE", "role-hierarchies");
            createMenu("menu.iam.password.policy", "/admin/password-policy", "", iamId, 6, "CORE", "password-policy");
            createMenu("menu.iam.system.settings", "/admin/system-settings", "", iamId, 7, "CORE", "system-settings");
            createMenu("menu.iam.menu.management", "/admin/menu-management", "", iamId, 8, "CORE", "menu-management");
            createMenu("menu.zerotrust.monitor", "/admin/security-monitor", "", securityId, 1, "CORE", "security-monitor");
            createMenu("menu.zerotrust.blacklist", "/admin/blacklist", "", securityId, 2, "CORE", "blacklist");
            createMenu("menu.security.sessions", "/admin/session-management", "", securityId, 3, "CORE", "session-management");
            createMenu("menu.security.ip", "/admin/ip-management", "", securityId, 4, "CORE", "ip-management");
            createMenu("menu.enterprise.zerotrust", "/admin/enterprise/zerotrust", "", securityId, 5, "ENTERPRISE", "enterprise-zerotrust");
            createMenu("menu.enterprise.incidents", "/admin/enterprise/incidents", "", securityId, 6, "ENTERPRISE", "enterprise-incidents");
            createMenu("menu.enterprise.home", "/admin/enterprise", "", enterpriseId, 1, "ENTERPRISE", "enterprise-home");
            createMenu("menu.enterprise.approvals", "/admin/enterprise/approvals", "", enterpriseId, 2, "ENTERPRISE", "enterprise-approvals");
            createMenu("menu.enterprise.mcp", "/admin/enterprise/mcp", "", enterpriseId, 3, "ENTERPRISE", "enterprise-mcp");
            createMenu("menu.enterprise.permits", "/admin/enterprise/permits", "", enterpriseId, 4, "ENTERPRISE", "enterprise-permits");
            createMenu("menu.enterprise.executions", "/admin/enterprise/executions", "", enterpriseId, 5, "ENTERPRISE", "enterprise-executions");
            createMenu("menu.enterprise.playbooks", "/admin/enterprise/playbooks", "", enterpriseId, 6, "ENTERPRISE", "enterprise-playbooks");
            createMenu("menu.enterprise.metrics", "/admin/enterprise/metrics", "", enterpriseId, 7, "ENTERPRISE", "enterprise-metrics");
            createMenu("menu.enterprise.integration", "/admin/enterprise/integration", "", enterpriseId, 8, "ENTERPRISE", "enterprise-integration");
            createMenu("menu.saas.tenants", "/admin/saas/tenants", "", saasId, 1, "SAAS", "saas-platform-tenants");
            createMenu("menu.saas.billing", "/admin/saas/billing", "", saasId, 2, "SAAS", "saas-platform-billing");
            createMenu("menu.saas.dedicated", "/admin/saas/dedicated", "", saasId, 3, "SAAS", "saas-platform-dedicated");
            createMenu("menu.saas.release.governance", "/admin/saas/release-governance", "", saasId, 4, "SAAS", "saas-release-governance");
            createMenu("menu.saas.tenant.workspace", "/admin/saas/tenant/workspace", "", saasId, 5, "SAAS", "saas-tenant-workspace");
        }

        ensureLearningMenus();
    }

    private void ensureLearningMenus() {
        if (!enterpriseEnabled || !saasEnabled) {
            return;
        }
        Long saasId = ensureMenu("menu.nav.saas", null, svgCloud(), null, 7, "SAAS", "saas");
        ensureMenu("menu.saas.learning", "/admin/saas/learning/overview", "", saasId, 6, "SAAS", "saas-learning-overview");
    }

    private Long createMenu(String name, String url, String icon, Long parentId, int order, String type, String dataPage) {
        AdminMenu menu = AdminMenu.builder()
                .name(name).url(url).icon(icon).parentId(parentId)
                .menuOrder(order).menuType(type).dataPage(dataPage).enabled(true)
                .build();
        Long id = menuRepository.save(menu).getId();
        menuQueryCache.invalidate();
        return id;
    }

    private Long ensureMenu(String name, String url, String icon, Long parentId, int order, String type, String dataPage) {
        Optional<AdminMenu> existingMenu = menuRepository.findByDataPage(dataPage);
        if (existingMenu.isPresent()) {
            AdminMenu menu = existingMenu.get();
            menu.setName(name);
            menu.setUrl(url);
            menu.setIcon(icon);
            menu.setParentId(parentId);
            menu.setMenuOrder(order);
            menu.setMenuType(type);
            menu.setDataPage(dataPage);
            menu.setEnabled(true);
            Long id = menuRepository.save(menu).getId();
            menuQueryCache.invalidate();
            return id;
        }
        return createMenu(name, url, icon, parentId, order, type, dataPage);
    }

    private String svgHome() { return "<svg fill=\"none\" stroke=\"currentColor\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.5\" d=\"M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25\"/></svg>"; }
    private String svgShield() { return "<svg fill=\"none\" stroke=\"currentColor\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.5\" d=\"M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z\"/></svg>"; }
    private String svgKey() { return "<svg fill=\"none\" stroke=\"currentColor\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.5\" d=\"M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z\"/></svg>"; }
    private String svgPeople() { return "<svg fill=\"none\" stroke=\"currentColor\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.5\" d=\"M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z\"/></svg>"; }
    private String svgEye() { return "<svg fill=\"none\" stroke=\"currentColor\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.5\" d=\"M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z\"/><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.5\" d=\"M15 12a3 3 0 11-6 0 3 3 0 016 0z\"/></svg>"; }
    private String svgBuilding() { return "<svg fill=\"none\" stroke=\"currentColor\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.5\" d=\"M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21\"/></svg>"; }
    private String svgCloud() { return "<svg fill=\"none\" stroke=\"currentColor\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.5\" d=\"M2.25 15a4.5 4.5 0 004.5 4.5H18a3.75 3.75 0 001.332-7.257 3 3 0 00-3.758-3.848 5.25 5.25 0 00-10.233 2.33A4.502 4.502 0 002.25 15z\"/></svg>"; }

    /**
     * Get menu tree filtered by user authorities and feature flags.
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<MenuNode> getMenuTreeForUser(Collection<? extends GrantedAuthority> authorities) {
        Set<String> userAuthorities = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        List<AdminMenu> allMenus = menuQueryCache.findAllWithRoles();

        List<AdminMenu> filtered = allMenus.stream()
                .filter(AdminMenu::isEnabled)
                .filter(m -> isMenuTypeAllowed(m.getMenuType()))
                .filter(m -> isMenuAllowedForUser(m, userAuthorities))
                .toList();

        return buildTree(filtered, null);
    }

    /**
     * Get all menus for management, filtered by enabled feature flags (enterprise/saas).
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<AdminMenu> getAllMenus() {
        return menuQueryCache.findAllWithRoles().stream()
                .filter(m -> isMenuTypeAllowed(m.getMenuType()))
                .toList();
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Optional<AdminMenu> getMenuById(Long id) {
        return menuRepository.findById(id);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public AdminMenu saveMenu(AdminMenu menu) {
        AdminMenu saved = menuRepository.save(menu);
        menuQueryCache.invalidate();
        return saved;
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void deleteMenu(Long id) {
        menuRepository.deleteByParentId(id);
        menuRepository.deleteById(id);
        menuQueryCache.invalidate();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void updateMenuOrder(Long menuId, int newOrder) {
        menuRepository.findById(menuId).ifPresent(menu -> {
            menu.setMenuOrder(newOrder);
            menuRepository.save(menu);
            menuQueryCache.invalidate();
        });
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void toggleEnabled(Long menuId) {
        menuRepository.findById(menuId).ifPresent(menu -> {
            menu.setEnabled(!menu.isEnabled());
            menuRepository.save(menu);
            menuQueryCache.invalidate();
        });
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void updateMenuRoles(Long menuId, Set<String> roleNames) {
        menuRepository.findById(menuId).ifPresent(menu -> {
            menu.clearRoles();
            if (roleNames != null) {
                roleNames.forEach(menu::addRole);
            }
            menuRepository.save(menu);
            menuQueryCache.invalidate();
        });
    }

    private boolean isMenuTypeAllowed(String menuType) {
        if ("CORE".equals(menuType)) return true;
        if ("ENTERPRISE".equals(menuType)) return enterpriseEnabled;
        if ("SAAS".equals(menuType)) return enterpriseEnabled && saasEnabled;
        return true;
    }

    private boolean isMenuAllowedForUser(AdminMenu menu, Set<String> userAuthorities) {
        Set<AdminMenuRole> roles = menu.getRoles();
        if (roles == null || roles.isEmpty()) return true;
        return roles.stream().anyMatch(r -> userAuthorities.contains(r.getRoleName()));
    }

    private List<MenuNode> buildTree(List<AdminMenu> menus, Long parentId) {
        return menus.stream()
                .filter(m -> Objects.equals(m.getParentId(), parentId))
                .map(m -> new MenuNode(
                        m.getId(), m.getName(), m.getUrl(), m.getIcon(),
                        m.getDataPage(), m.getMenuType(), m.isEnabled(),
                        m.getRoles().stream().map(AdminMenuRole::getRoleName).collect(Collectors.toSet()),
                        buildTree(menus, m.getId())
                ))
                .toList();
    }

    public record MenuNode(
            Long id, String name, String url, String icon,
            String dataPage, String menuType, boolean enabled,
            Set<String> roles, List<MenuNode> children
    ) {
        public boolean isGroup() {
            return url == null || url.isBlank();
        }

        public boolean hasChildren() {
            return children != null && !children.isEmpty();
        }
    }
}
