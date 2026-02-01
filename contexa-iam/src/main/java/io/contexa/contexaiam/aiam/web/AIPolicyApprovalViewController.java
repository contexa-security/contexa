package io.contexa.contexaiam.aiam.web;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
@RequestMapping("/admin/ai-policies")
@RequiredArgsConstructor
public class AIPolicyApprovalViewController {

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('POLICY_APPROVE')")
    public String aiPolicyApprovalPage(Model model) {
        
        model.addAttribute("pageTitle", "AI 정책 승인 관리");
        model.addAttribute("activeMenu", "ai-policy");

        return "admin/ai-policy-approval";
    }
}