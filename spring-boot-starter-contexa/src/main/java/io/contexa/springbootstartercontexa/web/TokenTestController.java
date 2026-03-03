package io.contexa.springbootstartercontexa.web;

import io.contexa.contexaidentity.security.token.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/token-test")
@RequiredArgsConstructor
public class TokenTestController {

    private final TokenService tokenService;

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "refreshToken is required"));
        }

        try {
            TokenService.RefreshResult result = tokenService.refresh(refreshToken);

            Map<String, Object> response = new HashMap<>();
            response.put("accessToken", result.accessToken());
            response.put("refreshToken", result.refreshToken());
            response.put("tokenType", "Bearer");
            response.put("expiresIn", tokenService.properties().getAccessTokenValidity());
            response.put("refreshExpiresIn", tokenService.properties().getRefreshTokenValidity());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("[TokenTest] Token refresh failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validate(
            @RequestHeader("Authorization") String authHeader) {

        String token = extractBearerToken(authHeader);
        if (token == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid Authorization header"));
        }

        Map<String, Object> response = new HashMap<>();
        boolean valid = tokenService.validateAccessToken(token);
        response.put("valid", valid);

        if (valid) {
            Authentication auth = tokenService.getAuthentication(token);
            if (auth != null) {
                response.put("username", auth.getName());
                List<String> authorities = auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();
                response.put("authorities", authorities);
            }
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> userinfo(
            @RequestHeader("Authorization") String authHeader) {

        String token = extractBearerToken(authHeader);
        if (token == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid Authorization header"));
        }

        try {
            Authentication auth = tokenService.getAuthentication(token);
            if (auth == null) {
                return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
            }

            Map<String, Object> response = new HashMap<>();
            response.put("username", auth.getName());
            response.put("authenticated", auth.isAuthenticated());
            List<String> authorities = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
            response.put("authorities", authorities);
            response.put("principal", auth.getPrincipal().getClass().getSimpleName());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("[TokenTest] Failed to extract userinfo from token", e);
            return ResponseEntity.status(401).body(Map.of("error", "Token validation failed"));
        }
    }

    private String extractBearerToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}
