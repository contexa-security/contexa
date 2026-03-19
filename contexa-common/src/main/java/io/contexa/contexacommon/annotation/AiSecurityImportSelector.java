package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;

import java.util.Map;

/**
 * Import selector that loads {@code AiSecurityConfiguration} and passes
 * {@code @EnableAISecurity} attribute values as system properties so they
 * can be read during bean creation phase (before the annotated class becomes a bean).
 */
public class AiSecurityImportSelector implements ImportSelector {

    private static final String AI_SECURITY_CONFIGURATION = "io.contexa.autoconfigure.ai.AiSecurityConfiguration";

    public static final String PROP_MODE = "contexa.security.mode";
    public static final String PROP_AUTH_BRIDGE = "contexa.security.auth-bridge";
    public static final String PROP_SESSION_USER_ATTR = "contexa.security.session-user-attribute";
    public static final String PROP_JWT_SECRET = "contexa.security.jwt-secret";
    public static final String PROP_AUTH_COOKIE_NAME = "contexa.security.auth-cookie-name";

    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        Map<String, Object> attrs = importingClassMetadata
                .getAnnotationAttributes(EnableAISecurity.class.getName());

        if (attrs != null) {
            Object modeObj = attrs.get("mode");
            if (modeObj instanceof SecurityMode mode) {
                System.setProperty(PROP_MODE, mode.name());
            }

            Object bridgeObj = attrs.get("authBridge");
            if (bridgeObj instanceof Class<?> bridgeClass) {
                System.setProperty(PROP_AUTH_BRIDGE, bridgeClass.getName());
            }

            Object sessionAttr = attrs.get("sessionUserAttribute");
            if (sessionAttr instanceof String s && !s.isBlank()) {
                System.setProperty(PROP_SESSION_USER_ATTR, s);
            }

            Object jwtSecret = attrs.get("jwtSecret");
            if (jwtSecret instanceof String s && !s.isBlank()) {
                System.setProperty(PROP_JWT_SECRET, s);
            }

            Object cookieName = attrs.get("authCookieName");
            if (cookieName instanceof String s && !s.isBlank()) {
                System.setProperty(PROP_AUTH_COOKIE_NAME, s);
            }
        }

        return new String[]{ AI_SECURITY_CONFIGURATION };
    }
}
