package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Locale;

public class OssOfficialSealedEvidenceCaptureFilter extends OncePerRequestFilter {

    public static final String PACKAGE_ID_HEADER = "X-Contexa-Sealed-Evidence-Package-Id";
    private static final Logger log = LoggerFactory.getLogger(OssOfficialSealedEvidenceCaptureFilter.class);

    private final OssOfficialSealedEvidenceCaptureService captureService;

    public OssOfficialSealedEvidenceCaptureFilter(OssOfficialSealedEvidenceCaptureService captureService) {
        this.captureService = captureService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        if (!shouldCapture(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            SealedEvidencePackage evidencePackage = captureService.capture(request);
            if (evidencePackage != null && StringUtils.hasText(evidencePackage.getPackageId())) {
                response.setHeader(PACKAGE_ID_HEADER, evidencePackage.getPackageId());
            }
        }
        catch (RuntimeException exception) {
            log.warn("[PQA OSS] Failed to capture official inspection sealed evidence. method={}, path={}",
                    request.getMethod(), request.getRequestURI(), exception);
        }
        filterChain.doFilter(request, response);
    }

    private boolean shouldCapture(HttpServletRequest request) {
        if (request == null) {
            return false;
        }
        String method = request.getMethod();
        if (!StringUtils.hasText(method)) {
            return false;
        }
        String normalizedMethod = method.trim().toUpperCase(Locale.ROOT);
        if ("OPTIONS".equals(normalizedMethod) || "HEAD".equals(normalizedMethod)) {
            return false;
        }
        String path = request.getRequestURI();
        if (!StringUtils.hasText(path)) {
            return false;
        }
        return path.startsWith("/api/")
                && !path.startsWith("/admin/")
                && !path.startsWith("/actuator/")
                && !path.startsWith("/api/health");
    }
}
