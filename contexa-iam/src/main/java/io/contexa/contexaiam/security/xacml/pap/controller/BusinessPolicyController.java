package io.contexa.contexaiam.security.xacml.pap.controller;

import io.contexa.contexaiam.admin.web.metadata.service.BusinessMetadataService;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.util.Map;
import java.util.HashMap;

@RequestMapping("/admin/authoring")
@RequiredArgsConstructor
public class BusinessPolicyController {

    private final BusinessPolicyService businessPolicyService;
    private final BusinessMetadataService businessMetadataService;

    @GetMapping("/policy-workbench")
    public String getPolicyAuthoringWorkbench(Model model) {
        model.addAttribute("allUsers", businessMetadataService.getAllUsersForPolicy());
        model.addAttribute("allGroups", businessMetadataService.getAllGroupsForPolicy());
        model.addAttribute("allResources", businessMetadataService.getAllBusinessResources());
        model.addAttribute("allActions", businessMetadataService.getAllBusinessActions());
        model.addAttribute("allConditions", businessMetadataService.getAllConditionTemplates());
        model.addAttribute("businessPolicyDto", new BusinessPolicyDto());

        return "admin/policy-authoring-workbench";
    }

    @PostMapping("/policy-workbench")
    public String createBusinessPolicy(@ModelAttribute("businessPolicyDto") BusinessPolicyDto businessPolicyDto, RedirectAttributes ra) {
        // [수정] 모델 어트리뷰트 이름 일치
        Policy newPolicy = businessPolicyService.createPolicyFromBusinessRule(businessPolicyDto);
        ra.addFlashAttribute("message", "비즈니스 정책 '" + newPolicy.getName() + "' 이(가) 성공적으로 생성되었습니다.");
        return "redirect:/admin/policies";
    }

    @RequestMapping("/api/admin/authoring")
    @RequiredArgsConstructor
    static class BusinessPolicyApiController {
        private final BusinessMetadataService businessMetadataService;

        @GetMapping("/metadata")
        public ResponseEntity<Map<String, Object>> getPolicyAuthoringMetadata() {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("subjects", businessMetadataService.getAllUsersAndGroups());
            metadata.put("resources", businessMetadataService.getAllBusinessResources());
            metadata.put("actions", businessMetadataService.getAllBusinessActions());
            metadata.put("conditionTemplates", businessMetadataService.getAllConditionTemplates());
            return ResponseEntity.ok(metadata);
        }
    }
}