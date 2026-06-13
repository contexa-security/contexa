/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.security.xacml.pap.controller;

import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.MessageSource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;


@Controller
@RequestMapping("/contexa/admin/policies")
@RequiredArgsConstructor
@Slf4j
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
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
        return "contexa/admin/policies";
    }

    @GetMapping("/register")
    public String registerForm(Model model, PolicyDto policyDto) {
        model.addAttribute("activePage", "policy-center");
        policyDto.getTargets().add(new TargetDto());
        policyDto.getRules().add(new RuleDto());
        model.addAttribute("policy", policyDto);
        return "contexa/admin/policydetails";
    }

    @PostMapping
    @Transactional(transactionManager = "contexaTransactionManager")
    public String createPolicy(@ModelAttribute PolicyDto policyDto, RedirectAttributes ra) {
        try {
            policyService.createPolicy(policyDto);
            ra.addFlashAttribute("message", msg("msg.policy.created"));
        } catch (DataIntegrityViolationException e) {
            log.error("Duplicate policy name", e);
            ra.addFlashAttribute("errorMessage", msg("msg.policy.name.duplicate"));
        } catch (Exception e) {
            log.error("Failed to create policy", e);
            ra.addFlashAttribute("errorMessage", msg("msg.policy.create.error", e.getMessage()));
        }
        return "redirect:/contexa/admin/policy-center?tab=list";
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
        return "contexa/admin/policydetails";
    }

    @PostMapping("/{id}/edit")
    @Transactional(transactionManager = "contexaTransactionManager")
    public String updatePolicy(@PathVariable Long id, @ModelAttribute PolicyDto policyDto, RedirectAttributes ra) {
        try {
            policyDto.setId(id);
            policyService.updatePolicy(policyDto);
            ra.addFlashAttribute("message", msg("msg.policy.updated"));
        } catch (DataIntegrityViolationException e) {
            log.error("Duplicate policy name on update", e);
            ra.addFlashAttribute("errorMessage", msg("msg.policy.name.duplicate"));
        } catch (Exception e) {
            log.error("Failed to update policy", e);
            ra.addFlashAttribute("errorMessage", msg("msg.policy.create.error", e.getMessage()));
        }
        return "redirect:/contexa/admin/policy-center?tab=list";
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
                TargetDto.builder()
                        .targetType(t.getTargetType())
                        .targetIdentifier(t.getTargetIdentifier())
                        .httpMethod(t.getHttpMethod() == null ? "ALL" : t.getHttpMethod())
                        .targetOrder(t.getTargetOrder())
                        .sourceType(t.getSourceType() != null ? t.getSourceType() : "RESOURCE")
                        .build()
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
    @Transactional(transactionManager = "contexaTransactionManager")
    public String deletePolicy(@PathVariable Long id,
                                @RequestParam(required = false) String changeReason,
                                RedirectAttributes ra) {
        try {
            policyService.deletePolicy(id, changeReason);
            ra.addFlashAttribute("message", msg("msg.policy.deleted"));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.policy.delete.error", e.getMessage()));
            log.error("Error deleting policy", e);
        }
        return "redirect:/contexa/admin/policy-center?tab=list";
    }

    @PostMapping("/{id}/approve")
    @Transactional(transactionManager = "contexaTransactionManager")
    public String approvePolicy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            String approver = extractCurrentUsername();
            policyService.approvePolicy(id, approver);
            ra.addFlashAttribute("message", msg("msg.policy.approved", id));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.error("Error approving policy", e);
        }
        return "redirect:/contexa/admin/policy-center?tab=list";
    }

    @PostMapping("/{id}/reject")
    @Transactional(transactionManager = "contexaTransactionManager")
    public String rejectPolicy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            String rejector = extractCurrentUsername();
            policyService.rejectPolicy(id, rejector);
            ra.addFlashAttribute("message", msg("msg.policy.rejected", id));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            log.error("Error rejecting policy", e);
        }
        return "redirect:/contexa/admin/policy-center?tab=list";
    }

    private String extractCurrentUsername() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return (auth != null && auth.getName() != null) ? auth.getName() : "SYSTEM";
    }
}
