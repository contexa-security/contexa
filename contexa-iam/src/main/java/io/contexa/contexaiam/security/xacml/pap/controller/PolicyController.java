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

import io.contexa.contexaiam.common.ConsoleFault;
import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.MessageSource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.support.RequestContextUtils;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.beans.factory.annotation.Qualifier;


@Controller
@RequestMapping("/contexa/admin/policies")
@Slf4j
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PolicyController {

    private static final String LIST = "redirect:/contexa/admin/policy-center?tab=list";
    private static final String DETAIL = "redirect:/contexa/admin/policies/";
    private static final Pattern EDIT_PATH = Pattern.compile("/contexa/admin/policies/(\\d+)/edit$");

    private final PolicyService policyService;
    private final ModelMapper modelMapper;
    private final MessageSource messageSource;


    public PolicyController(PolicyService policyService, @Qualifier("contexaModelMapper") ModelMapper modelMapper, MessageSource messageSource) {
        this.policyService = policyService;
        this.modelMapper = modelMapper;
        this.messageSource = messageSource;
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    /** The policy list is the policy center's list tab; the old list page was removed (c296a5cd6). */
    @GetMapping
    public String listPolicies() {
        return "redirect:/contexa/admin/policy-center?tab=list";
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
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
    public String createPolicy(@ModelAttribute PolicyDto policyDto, RedirectAttributes ra) {
        try {
            policyService.createPolicy(policyDto);
            ra.addFlashAttribute("message", msg("msg.policy.created"));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", failureText("msg.policy.create.error", e, "create a policy"));
        }
        return LIST;
    }

    /**
     * D01: a policy that is not there (deleted by another administrator, an old link) goes back to the list and says so,
     * looked up without an exception, which would mark this read-only transaction for rollback and end the request with
     * a server error. A refused edit comes back here with what was typed.
     */
    @GetMapping("/{id}")
    public String detailForm(@PathVariable Long id, Model model, RedirectAttributes ra) {
        Policy policy = policyService.findPolicy(id).orElse(null);
        if (policy == null) {
            log.warn("No policy with ID {}", id);
            ra.addFlashAttribute("errorMessage", msg("msg.policy.not.found", String.valueOf(id)));
            return LIST;
        }
        model.addAttribute("activePage", "policy-center");
        PolicyDto dto = toDto(policy);
        if (model.getAttribute("typedPolicy") instanceof PolicyDto typed) {
            keepTyped(dto, typed);
        }
        if (dto.getRules().isEmpty()) {
            dto.getRules().add(new RuleDto());
        }
        model.addAttribute("policy", dto);
        return "contexa/admin/policydetails";
    }

    /** D01: a refused or failed edit goes back to the policy's screen with the cause and what was typed. */
    @PostMapping("/{id}/edit")
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
    public String updatePolicy(@PathVariable Long id, @ModelAttribute PolicyDto policyDto, RedirectAttributes ra) {
        try {
            policyDto.setId(id);
            policyService.updatePolicy(policyDto);
            ra.addFlashAttribute("message", msg("msg.policy.updated"));
            return LIST;
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", failureText("msg.policy.update.error", e, "update policy " + id));
            ra.addFlashAttribute("typedPolicy", policyDto);
            return DETAIL + id;
        }
    }

    /**
     * D01: a form whose values cannot be bound (a number that is no number, an effect that does not exist) was answered
     * with a server error; it goes back to the screen it came from with the cause.
     */
    @ExceptionHandler(BindException.class)
    public String unboundForm(BindException refusal, HttpServletRequest request) {
        String fields = refusal.getFieldErrors().stream().map(FieldError::getField).distinct()
                .collect(Collectors.joining(", "));
        log.warn("Policy form refused, fields that cannot be read: {}", fields);
        RequestContextUtils.getOutputFlashMap(request).put("errorMessage", msg("msg.policy.form.invalid", fields));
        Matcher edit = EDIT_PATH.matcher(request.getRequestURI());
        return edit.find() ? DETAIL + edit.group(1) : LIST;
    }

    private static void keepTyped(PolicyDto shown, PolicyDto typed) {
        shown.setName(typed.getName());
        shown.setDescription(typed.getDescription());
        shown.setEffect(typed.getEffect());
        shown.setPriority(typed.getPriority());
        if (typed.getTargets() != null && !typed.getTargets().isEmpty()) {
            shown.setTargets(typed.getTargets());
        }
        if (typed.getRules() != null && !typed.getRules().isEmpty()) {
            shown.setRules(typed.getRules());
        }
    }

    /** A duplicate name is told as such; anything else in its own words or in general ones, logged by its kind. */
    private String failureText(String errorKey, Exception e, String doing) {
        if (e instanceof DataIntegrityViolationException && ConsoleFault.isDuplicate(e)) {
            log.warn("The console refused to {}: the name is taken", doing);
            return msg("msg.policy.name.duplicate");
        }
        return msg(errorKey, ConsoleFault.report(e, log, doing));
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
        // N-2: a list the screen can add its empty rule to; a policy without rules failed here with a server error.
        }).collect(Collectors.toList()));

        return dto;
    }

    @PostMapping("/delete/{id}")
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
    public String deletePolicy(@PathVariable Long id,
                                @RequestParam(required = false) String changeReason,
                                RedirectAttributes ra) {
        try {
            policyService.deletePolicy(id, changeReason);
            ra.addFlashAttribute("message", msg("msg.policy.deleted"));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", failureText("msg.policy.delete.error", e, "delete policy " + id));
        }
        return LIST;
    }

    @PostMapping("/{id}/approve")
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
    public String approvePolicy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            String approver = extractCurrentUsername();
            policyService.approvePolicy(id, approver);
            ra.addFlashAttribute("message", msg("msg.policy.approved", String.valueOf(id)));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", ConsoleFault.report(e, log, "approve policy " + id));
        }
        return LIST;
    }

    @PostMapping("/{id}/reject")
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
    public String rejectPolicy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            String rejector = extractCurrentUsername();
            policyService.rejectPolicy(id, rejector);
            ra.addFlashAttribute("message", msg("msg.policy.rejected", String.valueOf(id)));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", ConsoleFault.report(e, log, "reject policy " + id));
        }
        return LIST;
    }

    private String extractCurrentUsername() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return (auth != null && auth.getName() != null) ? auth.getName() : "SYSTEM";
    }
}
