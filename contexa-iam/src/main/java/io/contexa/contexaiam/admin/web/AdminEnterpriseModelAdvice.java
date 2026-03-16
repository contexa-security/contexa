package io.contexa.contexaiam.admin.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice(basePackages = "io.contexa")
public class AdminEnterpriseModelAdvice {

    private final boolean enterpriseEnabled;
    private final boolean saasEnabled;

    @Autowired
    public AdminEnterpriseModelAdvice(
            @Value("${contexa.enterprise.enabled:false}") boolean enterpriseEnabled,
            @Value("${contexa.saas.enabled:false}") boolean saasEnabled) {
        this.enterpriseEnabled = enterpriseEnabled;
        this.saasEnabled = saasEnabled;
    }

    public AdminEnterpriseModelAdvice(boolean enterpriseEnabled) {
        this(enterpriseEnabled, false);
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
