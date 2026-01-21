package io.contexa.contexaiam.admin.web.workflow.translator;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects; 
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class BusinessPolicyTranslatorImpl implements BusinessPolicyTranslator {

    private final PermissionRepository permissionRepository;

    @Override
    public Policy translate(WizardContext context) {
        Policy policy = Policy.builder()
                .name(context.sessionTitle()) 
                .description(context.sessionDescription()) 
                .effect(Policy.Effect.ALLOW)
                .priority(500)
                .build();

        List<String> conditions = new ArrayList<>();

        String subjectExpression = context.subjects().stream()
                .map(subject -> String.format("hasAuthority('%s_%d')", subject.type(), subject.id()))
                .collect(Collectors.joining(" or "));

        if (!subjectExpression.isEmpty()) {
            conditions.add("(" + subjectExpression + ")");
        }

        List<Permission> permissions = permissionRepository.findAllById(context.permissionIds());
        String permissionExpression = permissions.stream()
                .map(Permission::getName)
                .map(name -> String.format("hasAuthority('%s')", name))
                .collect(Collectors.joining(" and "));

        if (!permissionExpression.isEmpty()) {
            conditions.add("(" + permissionExpression + ")");
        }

        PolicyRule rule = PolicyRule.builder()
                .policy(policy)
                .description("Wizard-generated rule for: " + context.sessionDescription())
                .build();

        Set<PolicyCondition> policyConditions = conditions.stream()
                .map(expr -> PolicyCondition.builder().expression(expr).rule(rule).build())
                .collect(Collectors.toSet());
        rule.setConditions(policyConditions);

        Set<PolicyTarget> targets = permissions.stream()
                .map(Permission::getManagedResource) 
                .filter(Objects::nonNull) 
                .map(mr -> PolicyTarget.builder()
                        .policy(policy)
                        .targetType(mr.getResourceType().name())
                        .httpMethod(mr.getHttpMethod() != null ? mr.getHttpMethod().name() : null)
                        .targetIdentifier(mr.getResourceIdentifier())
                        .build())
                .collect(Collectors.toSet());

        policy.setRules(Set.of(rule));
        policy.setTargets(targets);

        return policy;
    }
}