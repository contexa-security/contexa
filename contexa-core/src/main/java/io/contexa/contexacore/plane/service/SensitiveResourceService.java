package io.contexa.contexacore.plane.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.annotation.Protectable;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * 민감 리소스 탐지 서비스 (AnnotationUtils 기반)
 *
 * @Protectable 어노테이션이 적용된 메서드를 런타임에 스캔하여
 * 하드코딩된 SENSITIVE_ACTIONS 목록을 대체합니다.
 *
 * 핵심 원칙:
 * 1. AnnotationUtils.findAnnotation()을 사용한 런타임 스캔 (MethodResourceScanner 패턴)
 * 2. SecurityEvent의 resourcePath를 @RequestMapping 경로와 매칭
 * 3. 1분 캐시 TTL로 성능 최적화
 *
 * 통합 지점:
 * - AntiEvasionSamplingEngine.isSensitiveAction()
 *
 * @author AI3Security
 * @since 3.0
 */
@Slf4j
@Service
public class SensitiveResourceService {

    @Autowired
    private ApplicationContext applicationContext;

    /**
     * Caffeine 캐시: 1분 TTL, 최대 10,000개 엔트리
     * Key: "httpMethod:resourcePath" (예: "POST:/api/users/{id}/delete")
     * Value: Boolean (true = @Protectable, false = not protected)
     */
    private final Cache<String, Boolean> protectableCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(1))
            .maximumSize(10_000)
            .recordStats()
            .build();

    /**
     * @Protectable 메서드 매핑 정보 저장
     * Key: "httpMethod:resourcePath" (정규화된 패턴)
     * Value: ProtectableMethodInfo
     */
    private final Map<String, ProtectableMethodInfo> protectableMethods = new ConcurrentHashMap<>();

    /**
     * 애플리케이션 시작 시 전체 @Protectable 메서드 스캔
     */
    @PostConstruct
    public void scanProtectableMethods() {
        log.info("[SensitiveResource] Starting @Protectable method scanning...");

        String[] beanNames = applicationContext.getBeanDefinitionNames();
        int scannedCount = 0;

        for (String beanName : beanNames) {
            Object bean;
            try {
                bean = applicationContext.getBean(beanName);
            } catch (Exception e) {
                continue;
            }

            Class<?> targetClass = AopUtils.getTargetClass(bean);

            // io.contexa.contexaiam. 패키지만 스캔 (MethodResourceScanner 패턴)
            if (!targetClass.getPackageName().startsWith("io.contexa.contexaiam")) {
                continue;
            }

            // 웹 컨트롤러만 스캔 (@Protectable은 주로 컨트롤러 메서드에 사용)
            boolean isController = AnnotationUtils.findAnnotation(targetClass, Controller.class) != null ||
                                   AnnotationUtils.findAnnotation(targetClass, RestController.class) != null;

            if (!isController) {
                continue; // 컨트롤러가 아니면 건너뜀
            }

            // 클래스 레벨 @RequestMapping 추출
            String classLevelPath = extractClassLevelPath(targetClass);

            try {
                for (Method method : targetClass.getDeclaredMethods()) {
                    // public 메서드만 대상
                    if (!Modifier.isPublic(method.getModifiers())) {
                        continue;
                    }

                    // @Protectable 어노테이션 체크 (MethodResourceScanner 패턴)
                    Protectable protectableAnnotation = AnnotationUtils.findAnnotation(method, Protectable.class);
                    if (protectableAnnotation == null) {
                        continue;
                    }

                    // HTTP 메서드 및 경로 추출
                    List<MethodPathMapping> mappings = extractMethodMappings(method, classLevelPath);

                    for (MethodPathMapping mapping : mappings) {
                        String key = buildCacheKey(mapping.httpMethod, mapping.path);

                        ProtectableMethodInfo info = ProtectableMethodInfo.builder()
                                .className(targetClass.getName())
                                .methodName(method.getName())
                                .httpMethod(mapping.httpMethod)
                                .path(mapping.path)
                                .pathPattern(convertToPathPattern(mapping.path))
                                .ownerField(protectableAnnotation.ownerField())
                                .build();

                        protectableMethods.put(key, info);
                        scannedCount++;

                        log.debug("[SensitiveResource] Found @Protectable: {} {} -> {}.{}",
                                mapping.httpMethod, mapping.path,
                                targetClass.getSimpleName(), method.getName());
                    }
                }
            } catch (Exception e) {
                log.warn("[SensitiveResource] Error scanning bean '{}': {}", beanName, e.getMessage());
            }
        }

        log.info("[SensitiveResource] Scanned {} @Protectable methods", scannedCount);
    }

    /**
     * SecurityEvent의 resourcePath와 httpMethod가
     * @Protectable 메서드를 대상으로 하는지 확인
     *
     * @param resourcePath 리소스 경로 (예: "/api/users/123/delete")
     * @param httpMethod HTTP 메서드 (예: "POST")
     * @return true = @Protectable 리소스, false = 일반 리소스
     */
    public boolean isProtectableResource(String resourcePath, String httpMethod) {
        if (resourcePath == null || httpMethod == null) {
            return false;
        }

        // 1. 캐시 조회
        String cacheKey = buildCacheKey(httpMethod, resourcePath);
        Boolean cached = protectableCache.getIfPresent(cacheKey);

        if (cached != null) {
            return cached;
        }

        // 2. @Protectable 메서드 매칭
        boolean isProtectable = matchProtectableMethod(resourcePath, httpMethod);

        // 3. 캐시 저장 (1분)
        protectableCache.put(cacheKey, isProtectable);

        return isProtectable;
    }

    /**
     * resourcePath를 @Protectable 메서드 패턴과 매칭
     */
    private boolean matchProtectableMethod(String resourcePath, String httpMethod) {
        String normalizedMethod = httpMethod.toUpperCase();

        // 정확히 일치하는 경로 먼저 확인
        String exactKey = buildCacheKey(normalizedMethod, resourcePath);
        if (protectableMethods.containsKey(exactKey)) {
            return true;
        }

        // 패턴 매칭 (예: /api/users/{id}/delete)
        for (Map.Entry<String, ProtectableMethodInfo> entry : protectableMethods.entrySet()) {
            ProtectableMethodInfo info = entry.getValue();

            if (!normalizedMethod.equals(info.httpMethod)) {
                continue;
            }

            if (info.pathPattern.matcher(resourcePath).matches()) {
                return true;
            }
        }

        return false;
    }

    /**
     * 클래스 레벨 @RequestMapping 경로 추출
     */
    private String extractClassLevelPath(Class<?> clazz) {
        RequestMapping requestMapping = AnnotationUtils.findAnnotation(clazz, RequestMapping.class);
        if (requestMapping != null && requestMapping.value().length > 0) {
            return normalizePath(requestMapping.value()[0]);
        }
        return "";
    }

    /**
     * 메서드 레벨 HTTP 매핑 추출
     * (@GetMapping, @PostMapping, @RequestMapping 등)
     */
    private List<MethodPathMapping> extractMethodMappings(Method method, String classLevelPath) {
        List<MethodPathMapping> mappings = new ArrayList<>();

        // @RequestMapping
        RequestMapping requestMapping = AnnotationUtils.findAnnotation(method, RequestMapping.class);
        if (requestMapping != null) {
            String[] paths = requestMapping.value().length > 0 ? requestMapping.value() : new String[]{""};
            RequestMethod[] methods = requestMapping.method().length > 0 ? requestMapping.method() : new RequestMethod[]{RequestMethod.GET};

            for (String path : paths) {
                for (RequestMethod rm : methods) {
                    String fullPath = combinePaths(classLevelPath, path);
                    mappings.add(new MethodPathMapping(rm.name(), fullPath));
                }
            }
            return mappings;
        }

        // @GetMapping
        GetMapping getMapping = AnnotationUtils.findAnnotation(method, GetMapping.class);
        if (getMapping != null) {
            for (String path : getMapping.value()) {
                String fullPath = combinePaths(classLevelPath, path);
                mappings.add(new MethodPathMapping("GET", fullPath));
            }
        }

        // @PostMapping
        PostMapping postMapping = AnnotationUtils.findAnnotation(method, PostMapping.class);
        if (postMapping != null) {
            for (String path : postMapping.value()) {
                String fullPath = combinePaths(classLevelPath, path);
                mappings.add(new MethodPathMapping("POST", fullPath));
            }
        }

        // @PutMapping
        PutMapping putMapping = AnnotationUtils.findAnnotation(method, PutMapping.class);
        if (putMapping != null) {
            for (String path : putMapping.value()) {
                String fullPath = combinePaths(classLevelPath, path);
                mappings.add(new MethodPathMapping("PUT", fullPath));
            }
        }

        // @DeleteMapping
        DeleteMapping deleteMapping = AnnotationUtils.findAnnotation(method, DeleteMapping.class);
        if (deleteMapping != null) {
            for (String path : deleteMapping.value()) {
                String fullPath = combinePaths(classLevelPath, path);
                mappings.add(new MethodPathMapping("DELETE", fullPath));
            }
        }

        // @PatchMapping
        PatchMapping patchMapping = AnnotationUtils.findAnnotation(method, PatchMapping.class);
        if (patchMapping != null) {
            for (String path : patchMapping.value()) {
                String fullPath = combinePaths(classLevelPath, path);
                mappings.add(new MethodPathMapping("PATCH", fullPath));
            }
        }

        return mappings;
    }

    /**
     * 경로 정규화
     */
    private String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        if (path.endsWith("/") && path.length() > 1) {
            path = path.substring(0, path.length() - 1);
        }
        return path;
    }

    /**
     * 클래스 레벨 + 메서드 레벨 경로 결합
     */
    private String combinePaths(String classPath, String methodPath) {
        String combined = normalizePath(classPath) + normalizePath(methodPath);
        return normalizePath(combined);
    }

    /**
     * Spring 경로 패턴을 정규표현식으로 변환
     * 예: /api/users/{id}/delete → /api/users/[^/]+/delete
     */
    private Pattern convertToPathPattern(String path) {
        String regex = path
                .replaceAll("\\{[^}]+\\}", "[^/]+")  // {id} → [^/]+
                .replaceAll("\\*\\*", ".*")           // ** → .*
                .replaceAll("\\*", "[^/]*");          // * → [^/]*

        return Pattern.compile("^" + regex + "$");
    }

    /**
     * 전체 @Protectable 리소스 목록 조회 (관리자용)
     */
    public Set<String> getAllProtectableResourcePaths() {
        return protectableMethods.keySet();
    }

    /**
     * 캐시 통계 조회 (모니터링용)
     */
    public CacheStats getCacheStats() {
        var stats = protectableCache.stats();
        return CacheStats.builder()
                .hitCount(stats.hitCount())
                .missCount(stats.missCount())
                .hitRate(stats.hitRate())
                .evictionCount(stats.evictionCount())
                .estimatedSize(protectableCache.estimatedSize())
                .protectableMethodCount(protectableMethods.size())
                .build();
    }

    /**
     * 캐시 수동 무효화
     */
    public void invalidateCache(String resourcePath, String httpMethod) {
        String cacheKey = buildCacheKey(httpMethod, resourcePath);
        protectableCache.invalidate(cacheKey);
    }

    /**
     * 전체 캐시 무효화
     */
    public void invalidateAllCache() {
        protectableCache.invalidateAll();
        log.warn("[SensitiveResource] All cache invalidated");
    }

    /**
     * @Protectable 메서드 재스캔 (런타임 갱신)
     */
    public void rescanProtectableMethods() {
        protectableMethods.clear();
        protectableCache.invalidateAll();
        scanProtectableMethods();
    }

    // ===== Helper Methods =====

    /**
     * 캐시 키 생성: "httpMethod:resourcePath"
     */
    private String buildCacheKey(String httpMethod, String resourcePath) {
        return (httpMethod != null ? httpMethod.toUpperCase() : "UNKNOWN") + ":" +
               normalizePath(resourcePath);
    }

    // ===== Inner Classes =====

    /**
     * HTTP 메서드 + 경로 매핑
     */
    private static class MethodPathMapping {
        final String httpMethod;
        final String path;

        MethodPathMapping(String httpMethod, String path) {
            this.httpMethod = httpMethod;
            this.path = path;
        }
    }

    /**
     * @Protectable 메서드 정보
     */
    @lombok.Builder
    @lombok.Getter
    private static class ProtectableMethodInfo {
        private final String className;
        private final String methodName;
        private final String httpMethod;
        private final String path;
        private final Pattern pathPattern;
        private final String ownerField;
    }

    /**
     * 캐시 통계 클래스
     */
    @lombok.Builder
    @lombok.Getter
    public static class CacheStats {
        private final long hitCount;
        private final long missCount;
        private final double hitRate;
        private final long evictionCount;
        private final long estimatedSize;
        private final int protectableMethodCount;
    }
}
