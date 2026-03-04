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
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/policies")
@RequiredArgsConstructor
public class PolicyApiController {

    private final BusinessPolicyService businessPolicyService;
    private final ModelMapper modelMapper;

    @PostMapping("/build-from-business-rule")
    public ResponseEntity<PolicyDto> buildPolicyFromBusinessRule(@RequestBody BusinessPolicyDto dto) {
        try {
                        
            Policy createdPolicy = businessPolicyService.createPolicyFromBusinessRule(dto);

            PolicyDto responseDto = modelMapper.map(createdPolicy, PolicyDto.class);

            return ResponseEntity.ok(responseDto);

        } catch (Exception e) {
            log.error("Error occurred while processing policy creation API", e);
            
            return ResponseEntity.badRequest().build();
        }
    }

}
