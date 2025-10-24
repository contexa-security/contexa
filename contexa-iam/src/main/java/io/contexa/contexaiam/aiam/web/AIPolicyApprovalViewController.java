package io.contexa.contexaiam.aiam.web;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * AI Policy Approval View Controller
 *
 * AI 정책 승인 관리 UI를 제공하는 뷰 컨트롤러입니다.
 *
 * @author AI3Security
 * @since 3.1.0
 */
@Slf4j
@Controller
@RequestMapping("/admin/ai-policies")
@RequiredArgsConstructor
public class AIPolicyApprovalViewController {

    /**
     * AI 정책 승인 관리 페이지
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('POLICY_APPROVE')")
    public String aiPolicyApprovalPage(Model model) {
        log.info("AI 정책 승인 관리 페이지 접근");

        model.addAttribute("pageTitle", "AI 정책 승인 관리");
        model.addAttribute("activeMenu", "ai-policy");

        return "admin/ai-policy-approval";
    }
}