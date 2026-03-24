package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;

import java.util.Map;

/**
 * Import selector that loads {@code AiSecurityConfiguration} by class name.
 * <p>
 * This selector exists in contexa-common because {@code @EnableAISecurity} resides here,
 * but the actual configuration class is in contexa-autoconfigure module.
 * Using string-based class name avoids a compile-time dependency on contexa-autoconfigure.
 * </p>
 */
public class AiSecurityImportSelector implements ImportSelector {

    public static final String PROP_MODE = "contexa.ai.security.mode";
    private static final String AI_SECURITY_CONFIGURATION = "io.contexa.autoconfigure.ai.AiSecurityConfiguration";

    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        Map<String, Object> attributes = importingClassMetadata.getAnnotationAttributes(EnableAISecurity.class.getName(), false);
        SecurityMode mode = SecurityMode.SANDBOX;
        if (attributes != null) {
            Object declaredMode = attributes.get("mode");
            if (declaredMode instanceof SecurityMode securityMode) {
                mode = securityMode;
            }
        }
        System.setProperty(PROP_MODE, mode.name());
        return new String[]{ AI_SECURITY_CONFIGURATION };
    }
}
