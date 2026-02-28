package io.contexa.contexaiam.admin.web;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice(basePackages = "io.contexa.contexaiam.admin")
public class AdminEnterpriseModelAdvice {

    private final boolean enterpriseEnabled;

    public AdminEnterpriseModelAdvice(boolean enterpriseEnabled) {
        this.enterpriseEnabled = enterpriseEnabled;
    }

    @ModelAttribute("contexaAdminEnterpriseEnabled")
    public boolean contexaAdminEnterpriseEnabled() {
        return enterpriseEnabled;
    }
}
