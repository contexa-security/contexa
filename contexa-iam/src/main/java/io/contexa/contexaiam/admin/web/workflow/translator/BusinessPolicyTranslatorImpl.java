package io.contexa.contexaiam.admin.web.workflow.translator;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects; // [신규] import 추가
import java.util.Set;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class BusinessPolicyTranslatorImpl implements BusinessPolicyTranslator {

    private final PermissionRepository permissionRepository;

    @Override
    public Policy translate(WizardContext context) {
        Policy policy = Policy.builder()
                .name(context.sessionTitle()) // [수정] policyName() -> sessionTitle()
                .description(context.sessionDescription()) // [수정] policyDescription() -> sessionDescription()
                .effect(Policy.Effect.ALLOW)
                .priority(500)
                .build();

        List<String> conditions = new ArrayList<>();

        // 주체(Who) SpEL 조건 생성
        String subjectExpression = context.subjects().stream()
                .map(subject -> String.format("hasAuthority('%s_%d')", subject.type(), subject.id()))
                .collect(Collectors.joining(" or "));

        if (!subjectExpression.isEmpty()) {
            conditions.add("(" + subjectExpression + ")");
        }

        // 권한(What) SpEL 조건 생성
        List<Permission> permissions = permissionRepository.findAllById(context.permissionIds());
        String permissionExpression = permissions.stream()
                .map(Permission::getName)
                .map(name -> String.format("hasAuthority('%s')", name))
                .collect(Collectors.joining(" and "));

        if (!permissionExpression.isEmpty()) {
            conditions.add("(" + permissionExpression + ")");
        }

        // 규칙(Rule) 엔티티 생성
        PolicyRule rule = PolicyRule.builder()
                .policy(policy)
                .description("Wizard-generated rule for: " + context.sessionDescription())
                .build();

        Set<PolicyCondition> policyConditions = conditions.stream()
                .map(expr -> PolicyCondition.builder().expression(expr).rule(rule).build())
                .collect(Collectors.toSet());
        rule.setConditions(policyConditions);

        // [수정] 대상(Target) 엔티티 생성 로직 변경
        // p.getFunctions() 대신, Permission에 직접 연결된 ManagedResource를 사용합니다.
        Set<PolicyTarget> targets = permissions.stream()
                .map(Permission::getManagedResource) // 1:1 관계인 ManagedResource를 직접 가져옵니다.
                .filter(Objects::nonNull) // ManagedResource가 없는 경우를 대비해 null을 필터링합니다.
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