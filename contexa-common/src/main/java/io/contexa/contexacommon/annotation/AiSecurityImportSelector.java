package io.contexa.contexacommon.annotation;

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;

/**
 * Import selector that loads {@code AiSecurityConfiguration} by class name.
 * <p>
 * This selector exists in contexa-common because {@code @EnableAISecurity} resides here,
 * but the actual configuration class is in contexa-autoconfigure module.
 * Using string-based class name avoids a compile-time dependency on contexa-autoconfigure.
 * </p>
 */
public class AiSecurityImportSelector implements ImportSelector {

    private static final String AI_SECURITY_CONFIGURATION = "io.contexa.autoconfigure.ai.AiSecurityConfiguration";

    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        return new String[]{ AI_SECURITY_CONFIGURATION };
    }
}
