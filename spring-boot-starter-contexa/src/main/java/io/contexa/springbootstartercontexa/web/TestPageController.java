package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacommon.security.authority.PermissionAuthority;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.stream.Collectors;

/**
 * 보안 테스트 페이지 컨트롤러
 *
 * Thymeleaf 템플릿을 사용하여 보안 테스트 UI를 렌더링한다.
 * 인증된 사용자만 접근 가능하며, 사용자 정보를 모델에 전달한다.
 */
@Slf4j
@Controller
public class TestPageController {

    /**
     * 보안 테스트 페이지
     *
     * @Protectable 어노테이션이 적용된 메서드들을 테스트하는 UI를 제공한다.
     *
     * 기능:
     * - 현재 Action 상태 조회
     * - Action 강제 설정 (ALLOW, BLOCK, MONITOR 등)
     * - 각 AnalysisRequirement 레벨별 API 테스트
     * - 실행 결과 로그 표시
     *
     * @param model Thymeleaf 모델
     * @return 템플릿 경로
     */
    @GetMapping("/test/token")
    public String tokenTestPage() {
        return "test/token-test";
    }

    @GetMapping("/test/security")
    public String securityTestPage(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        String username = "anonymous";
        String urlAuthorities = "";
        String methodAuthorities = "";

        if (auth != null && auth.isAuthenticated()) {
            username = auth.getName();

            // URL 권한 (RoleAuthority) - 행 단위로 표시
            urlAuthorities = auth.getAuthorities().stream()
                .filter(a -> a instanceof RoleAuthority)
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining("\n"));

            // 서비스/METHOD 권한 (PermissionAuthority) - 행 단위로 표시
            methodAuthorities = auth.getAuthorities().stream()
                .filter(a -> a instanceof PermissionAuthority)
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining("\n"));
        }

        model.addAttribute("username", username);
        model.addAttribute("urlAuthorities", urlAuthorities.isEmpty() ? "-" : urlAuthorities);
        model.addAttribute("methodAuthorities", methodAuthorities.isEmpty() ? "-" : methodAuthorities);

        log.info("[보안 테스트 페이지] 접근 - user: {}, url: {}, method: {}", username, urlAuthorities, methodAuthorities);

        return "test/security-test";
    }
}
