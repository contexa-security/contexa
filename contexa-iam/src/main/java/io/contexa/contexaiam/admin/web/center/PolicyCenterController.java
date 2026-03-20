package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Policy Center - unified policy management controller.
 * Combines Resource Workbench, Policy Builder, Policy List, and Authorization Studio
 * into a single integrated interface.
 */
@Controller
@RequestMapping("/admin/policy-center")
@RequiredArgsConstructor
@Slf4j
public class PolicyCenterController {

    private final ResourceRegistryService resourceRegistryService;
    private final PolicyService policyService;
    private final RoleService roleService;

    @GetMapping
    public String policyCenter(
            @RequestParam(required = false, defaultValue = "resources") String tab,
            @ModelAttribute("criteria") ResourceSearchCriteria criteria,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
            Model model) {

        model.addAttribute("activePage", "policy-center");
        model.addAttribute("activeTab", tab);

        try {
            // Resources tab data
            Page<ManagedResource> resourcePage = resourceRegistryService.findResources(criteria, pageable);
            Set<String> serviceOwners = resourceRegistryService.getAllServiceOwners();
            model.addAttribute("resourcePage", resourcePage);
            model.addAttribute("serviceOwners", serviceOwners);
            model.addAttribute("criteria", criteria);

            // Policy creation tab data
            List<Role> roles = roleService.getRolesWithoutExpression();
            model.addAttribute("roles", roles);

            // Policy list tab data
            model.addAttribute("policies", policyService.getAllPolicies());
        } catch (Exception e) {
            log.error("Failed to load policy center data", e);
            model.addAttribute("resourcePage", Page.empty());
            model.addAttribute("serviceOwners", Collections.emptySet());
            model.addAttribute("roles", Collections.emptyList());
            model.addAttribute("policies", Collections.emptyList());
            model.addAttribute("errorMessage", "Failed to load data. Please try again.");
        }

        return "admin/policy-center";
    }
}
