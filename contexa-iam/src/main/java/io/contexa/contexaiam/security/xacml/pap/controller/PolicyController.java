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
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin/policies")
@RequiredArgsConstructor
@Slf4j
public class PolicyController {

    private final PolicyService policyService;
    private final ModelMapper modelMapper;

    @GetMapping
    public String listPolicies(Model model) {
        List<Policy> policies = policyService.getAllPolicies();
        List<PolicyDto> dtoList = policies.stream()
                .map(p -> modelMapper.map(p, PolicyDto.class))
                .collect(Collectors.toList());
        model.addAttribute("policies", dtoList);
        return "admin/policies";
    }

    @GetMapping("/register")
    public String registerForm(Model model, PolicyDto policyDto) {
        policyDto.getTargets().add(new TargetDto());
        policyDto.getRules().add(new RuleDto());
        model.addAttribute("policy", policyDto);
        return "admin/policydetails";
    }

    @PostMapping
    public String createPolicy(@ModelAttribute PolicyDto policyDto, RedirectAttributes ra) {
        policyService.createPolicy(policyDto);
        ra.addFlashAttribute("message", "정책이 성공적으로 생성되었습니다.");
        return "redirect:/admin/policies";
    }

    @GetMapping("/{id}")
    public String detailForm(@PathVariable Long id, Model model) {
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
        ra.addFlashAttribute("message", "정책이 성공적으로 수정되었습니다.");
        return "redirect:/admin/policies";
    }

    private PolicyDto toDto(Policy policy) {
        PolicyDto dto = new PolicyDto();
        dto.setId(policy.getId());
        dto.setName(policy.getName());
        dto.setDescription(policy.getDescription());
        dto.setEffect(policy.getEffect());
        dto.setPriority(policy.getPriority());

        dto.setTargets(policy.getTargets().stream().map(t ->
                new TargetDto(t.getTargetType(), t.getTargetIdentifier(), t.getHttpMethod() == null ? "ALL" : t.getHttpMethod())
        ).collect(Collectors.toList()));

        dto.setRules(policy.getRules().stream().map(rule -> {
            RuleDto ruleDto = new RuleDto();
            ruleDto.setDescription(rule.getDescription());

            // PolicyCondition 엔티티를 ConditionDto로 변환
            List<ConditionDto> conditionDtos = rule.getConditions().stream()
                    .map(condition -> new ConditionDto(condition.getExpression(), condition.getAuthorizationPhase()))
                    .collect(Collectors.toList());
            ruleDto.setConditions(conditionDtos);

            return ruleDto;
        }).toList());

        return dto;
    }

    @GetMapping("/delete/{id}")
    public String deletePolicy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            policyService.deletePolicy(id);
            ra.addFlashAttribute("message", "정책이 성공적으로 삭제되었습니다.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "정책 삭제 실패: " + e.getMessage());
            log.error("Error deleting policy", e);
        }
        return "redirect:/admin/policies";
    }
}
