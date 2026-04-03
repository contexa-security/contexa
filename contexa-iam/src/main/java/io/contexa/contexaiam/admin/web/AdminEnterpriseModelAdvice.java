package io.contexa.contexaiam.admin.web;

import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.util.Collections;
import java.util.List;

@ControllerAdvice(basePackages = "io.contexa")
public class AdminEnterpriseModelAdvice {

    private final boolean enterpriseEnabled;
    private final boolean saasEnabled;
    @Nullable
    private final AdminMenuService adminMenuService;

    public AdminEnterpriseModelAdvice(boolean enterpriseEnabled, boolean saasEnabled,
                                      @Nullable AdminMenuService adminMenuService) {
        this.enterpriseEnabled = enterpriseEnabled;
        this.saasEnabled = saasEnabled;
        this.adminMenuService = adminMenuService;
    }

    @ModelAttribute("menuTree")
    public List<AdminMenuService.MenuNode> menuTree() {
        if (adminMenuService == null) return Collections.emptyList();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return Collections.emptyList();
        try {
            return adminMenuService.getMenuTreeForUser(auth.getAuthorities());
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    @ModelAttribute("contexaAdminEnterpriseEnabled")
    public boolean contexaAdminEnterpriseEnabled() {
        return enterpriseEnabled;
    }

    @ModelAttribute("contexaAdminSaasEnabled")
    public boolean contexaAdminSaasEnabled() {
        return enterpriseEnabled && saasEnabled;
    }

    @ModelAttribute("contexaEnterpriseActiveSection")
    public String contexaEnterpriseActiveSection() {
        return enterpriseEnabled ? "enterprise" : "";
    }

    @ModelAttribute("contexaEnterpriseActivePage")
    public String contexaEnterpriseActivePage() {
        return "";
    }

    @ModelAttribute("contexaEnterpriseHasSoar")
    public boolean contexaEnterpriseHasSoar() {
        return enterpriseEnabled;
    }

    @ModelAttribute("contexaEnterpriseHasMcp")
    public boolean contexaEnterpriseHasMcp() {
        return enterpriseEnabled;
    }

    @ModelAttribute("contexaEnterpriseHasApproval")
    public boolean contexaEnterpriseHasApproval() {
        return enterpriseEnabled;
    }

    @ModelAttribute("contexaEnterpriseHasPermit")
    public boolean contexaEnterpriseHasPermit() {
        return enterpriseEnabled;
    }

    @ModelAttribute("contexaEnterpriseHasDashboards")
    public boolean contexaEnterpriseHasDashboards() {
        return enterpriseEnabled;
    }
}
