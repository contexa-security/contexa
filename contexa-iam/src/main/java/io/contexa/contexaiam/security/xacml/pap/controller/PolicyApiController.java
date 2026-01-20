package io.contexa.contexaiam.security.xacml.pap.controller;

import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;


@Slf4j
@RequestMapping("/api/policies") 
@RequiredArgsConstructor
public class PolicyApiController {

    private final BusinessPolicyService businessPolicyService;
    private final ModelMapper modelMapper;

    
    @PostMapping("/build-from-business-rule")
    public ResponseEntity<PolicyDto> buildPolicyFromBusinessRule(@RequestBody BusinessPolicyDto dto) {
        try {
            log.info("Received request to build policy from business rule: {}", dto.getPolicyName());
            
            Policy createdPolicy = businessPolicyService.createPolicyFromBusinessRule(dto);

            
            PolicyDto responseDto = modelMapper.map(createdPolicy, PolicyDto.class);

            
            return ResponseEntity.ok(responseDto);

        } catch (Exception e) {
            log.error("정책 생성 API 처리 중 오류 발생", e);
            
            return ResponseEntity.badRequest().build();
        }
    }

    
    
    
}
