package io.contexa.contexaiam.security.xacml.pap.controller;

import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Controller;

@Controller
@RequestMapping("/admin/policies")
@RequiredArgsConstructor
@Slf4j
public class PolicyController {

    private final PolicyService policyService;
    private final ModelMapper modelMapper;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String listPolicies(Model model) {
        model.addAttribute("activePage", "policy-center");
        List<Policy> policies = policyService.getAllPolicies();
        List<PolicyDto> dtoList = policies.stream()
                .map(p -> modelMapper.map(p, PolicyDto.class))
                .collect(Collectors.toList());
        model.addAttribute("policies", dtoList);
        return "admin/policies";
    }

    @GetMapping("/register")
    public String registerForm(Model model, PolicyDto policyDto) {
        model.addAttribute("activePage", "policy-center");
        policyDto.getTargets().add(new TargetDto());
        policyDto.getRules().add(new RuleDto());
        model.addAttribute("policy", policyDto);
        return "admin/policydetails";
    }

    @PostMapping
    public String createPolicy(@ModelAttribute PolicyDto policyDto, RedirectAttributes ra) {
        policyService.createPolicy(policyDto);
        ra.addFlashAttribute("message", msg("msg.policy.created"));
        return "redirect:/admin/policies";
    }

    @GetMapping("/{id}")
    public String detailForm(@PathVariable Long id, Model model) {
        model.addAttribute("activePage", "policy-center");
        Policy policy = policyService.findById(id);
        PolicyDto dto = toDto(policy);
        if (dto.getRules().isEmpty()) {
            dto.getRules().add(new RuleDto());
        }
        model.addAttribute("policy", dto);
        return "admin/policydetails";
    }

    @PostMapping("/{id}/edit")
    public String updatePolicy(@PathVariable Long id, @ModelAttribute PolicyDto policyDto, RedirectAttributes ra) {
        policyDto.setId(id);
        policyService.updatePolicy(policyDto);
        ra.addFlashAttribute("message", msg("msg.policy.updated"));
        return "redirect:/admin/policies";
    }

    private PolicyDto toDto(Policy policy) {
        PolicyDto dto = new PolicyDto();
        dto.setId(policy.getId());
        dto.setName(policy.getName());
        dto.setDescription(policy.getDescription());
        dto.setEffect(policy.getEffect());
        dto.setPriority(policy.getPriority());

        dto.setSource(policy.getSource());
        dto.setApprovalStatus(policy.getApprovalStatus());
        dto.setIsActive(policy.getIsActive());
        dto.setFriendlyDescription(policy.getFriendlyDescription());
        dto.setApprovedBy(policy.getApprovedBy());
        dto.setApprovedAt(policy.getApprovedAt());
        dto.setConfidenceScore(policy.getConfidenceScore());
        dto.setAiModel(policy.getAiModel());
        dto.setReasoning(policy.getReasoning());
        dto.setCreatedAt(policy.getCreatedAt());
        dto.setUpdatedAt(policy.getUpdatedAt());

        dto.setTargets(policy.getTargets().stream().map(t ->
                new TargetDto(t.getTargetType(), t.getTargetIdentifier(), t.getHttpMethod() == null ? "ALL" : t.getHttpMethod())
        ).collect(Collectors.toList()));

        dto.setRules(policy.getRules().stream().map(rule -> {
            RuleDto ruleDto = new RuleDto();
            ruleDto.setDescription(rule.getDescription());

            List<ConditionDto> conditionDtos = rule.getConditions().stream()
                    .map(condition -> new ConditionDto(condition.getExpression(), condition.getAuthorizationPhase()))
                    .collect(Collectors.toList());
            ruleDto.setConditions(conditionDtos);

            return ruleDto;
        }).toList());

        return dto;
    }

    @PostMapping("/delete/{id}")
    public String deletePolicy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            policyService.deletePolicy(id);
            ra.addFlashAttribute("message", msg("msg.policy.deleted"));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.policy.delete.error", e.getMessage()));
            log.error("Error deleting policy", e);
        }
        return "redirect:/admin/policies";
    }

    @PostMapping("/{id}/approve")
    public String approvePolicy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            String approver = extractCurrentUsername();
            policyService.approvePolicy(id, approver);
            ra.addFlashAttribute("message", msg("msg.policy.approved", id));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.error("Error approving policy", e);
        }
        return "redirect:/admin/policies";
    }

    @PostMapping("/{id}/reject")
    public String rejectPolicy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            String rejector = extractCurrentUsername();
            policyService.rejectPolicy(id, rejector);
            ra.addFlashAttribute("message", msg("msg.policy.rejected", id));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.error("Error rejecting policy", e);
        }
        return "redirect:/admin/policies";
    }

    private String extractCurrentUsername() {
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        return (auth != null && auth.getName() != null) ? auth.getName() : "SYSTEM";
    }
}
