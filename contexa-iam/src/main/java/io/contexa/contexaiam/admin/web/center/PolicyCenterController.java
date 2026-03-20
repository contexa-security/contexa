package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.admin.web.studio.service.StudioExplorerService;
import io.contexa.contexaiam.admin.web.studio.service.StudioVisualizerService;
import io.contexa.contexaiam.admin.web.studio.service.StudioActionService;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
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
    private final PermissionService permissionService;
    private final PermissionCatalogService permissionCatalogService;
    private final ConditionCompatibilityService conditionCompatibilityService;
    private final StudioExplorerService explorerService;
    private final StudioVisualizerService visualizerService;
    private final StudioActionService actionService;

    @GetMapping
    public String policyCenter(
            @RequestParam(required = false, defaultValue = "resources") String tab,
            @ModelAttribute("criteria") ResourceSearchCriteria criteria,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
            Model model) {

        model.addAttribute("activePage", "policy-center");
        model.addAttribute("activeTab", tab);

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

        return "admin/policy-center";
    }
}
