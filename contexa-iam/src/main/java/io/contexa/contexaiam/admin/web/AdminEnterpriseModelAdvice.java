package io.contexa.contexaiam.admin.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice(basePackages = "io.contexa.contexaiam.admin")
public class AdminEnterpriseModelAdvice {

    @Value("${contexa.enterprise.enabled:false}")
    private boolean enterpriseEnabled;

    @ModelAttribute("contexaAdminEnterpriseEnabled")
    public boolean contexaAdminEnterpriseEnabled() {
        return enterpriseEnabled;
    }
}
