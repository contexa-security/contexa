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

/**
 * [신규] 정책 빌더와 같은 비동기 클라이언트 요청을 처리하기 위한 API 전용 컨트롤러
 */
@Slf4j
@RestController
@RequestMapping("/api/policies") // JavaScript가 호출하는 기본 경로
@RequiredArgsConstructor
public class PolicyApiController {

    private final BusinessPolicyService businessPolicyService;
    private final ModelMapper modelMapper;

    /**
     * 지능형 정책 빌더에서 전송된 BusinessPolicyDto를 받아 실제 정책을 생성합니다.
     * @param dto 클라이언트의 정책 빌더에서 구성된 데이터
     * @return 생성된 정책 정보를 담은 PolicyDto
     */
    @PostMapping("/build-from-business-rule")
    public ResponseEntity<PolicyDto> buildPolicyFromBusinessRule(@RequestBody BusinessPolicyDto dto) {
        try {
            log.info("Received request to build policy from business rule: {}", dto.getPolicyName());
            // 1. 비즈니스 서비스를 호출하여 정책을 생성합니다.
            Policy createdPolicy = businessPolicyService.createPolicyFromBusinessRule(dto);

            // 2. 생성된 Policy 엔티티를 클라이언트에 전달할 PolicyDto로 변환합니다.
            PolicyDto responseDto = modelMapper.map(createdPolicy, PolicyDto.class);

            // 3. 성공 응답(200 OK)과 함께 생성된 정책 정보를 JSON으로 반환합니다.
            return ResponseEntity.ok(responseDto);

        } catch (Exception e) {
            log.error("정책 생성 API 처리 중 오류 발생", e);
            // 오류 발생 시 400 Bad Request 또는 500 Internal Server Error 응답
            return ResponseEntity.badRequest().build();
        }
    }

    // TODO: 향후 AI 자연어 정책 생성 API 엔드포인트도 이 컨트롤러에 추가할 수 있습니다.
    // @PostMapping("/generate-from-text")
    // public ResponseEntity<AiGeneratedPolicyDraftDto> generatePolicyFromText(...)
}
