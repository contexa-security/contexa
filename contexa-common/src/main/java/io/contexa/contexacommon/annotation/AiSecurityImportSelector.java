package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.security.bridge.old.SecurityMode;
import org.springframework.context.annotation.ImportSelector;
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

    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        Map<String, Object> attrs = importingClassMetadata
                .getAnnotationAttributes(EnableAISecurity.class.getName());

        if (attrs != null) {
            Object modeObj = attrs.get("mode");
            if (modeObj instanceof SecurityMode mode) {
                System.setProperty(PROP_MODE, mode.name());
            }
        }

        return new String[]{ AI_SECURITY_CONFIGURATION };
    }
}
