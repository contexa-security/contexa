package io.contexa.autoconfigure.iam.admin;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.ui.Model;

@ControllerAdvice
public final class PromptQualityRouteModelAdvice {

    private final PromptQualityRouteProperties properties;

    public PromptQualityRouteModelAdvice(PromptQualityRouteProperties properties) {
        this.properties = properties;
    }

    @ModelAttribute
    public void addPromptQualityRoutes(Model model) {
        if (!model.containsAttribute("pqaOfficialApiRoot")) {
            model.addAttribute("pqaOfficialApiRoot", properties.getOfficialApiRoot());
        }
        if (!model.containsAttribute("pqaEnterpriseApiRoot")) {
            model.addAttribute("pqaEnterpriseApiRoot", properties.getEnterpriseApiRoot());
        }
    }
}
