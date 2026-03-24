package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.security.bridge.AuthObjectLocation;
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
    public static final String PROP_AUTH_OBJECT_LOCATION = "contexa.ai.security.auth-object.location";
    public static final String PROP_AUTH_OBJECT_ATTRIBUTE = "contexa.ai.security.auth-object.attribute";
    public static final String PROP_AUTH_OBJECT_TYPE = "contexa.ai.security.auth-object.type";
    private static final String AI_SECURITY_CONFIGURATION = "io.contexa.autoconfigure.ai.AiSecurityConfiguration";

    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        Map<String, Object> attributes = importingClassMetadata.getAnnotationAttributes(EnableAISecurity.class.getName(), false);
        SecurityMode mode = SecurityMode.SANDBOX;
        AuthObjectLocation authObjectLocation = AuthObjectLocation.AUTO;
        String authObjectAttribute = "";
        String authObjectType = Object.class.getName();
        if (attributes != null) {
            Object declaredMode = attributes.get("mode");
            if (declaredMode instanceof SecurityMode securityMode) {
                mode = securityMode;
            }
            Object declaredLocation = attributes.get("authObjectLocation");
            if (declaredLocation instanceof AuthObjectLocation objectLocation) {
                authObjectLocation = objectLocation;
            }
            Object declaredAttribute = attributes.get("authObjectAttribute");
            if (declaredAttribute instanceof String attributeName) {
                authObjectAttribute = attributeName;
            }
            Object declaredType = attributes.get("authObjectType");
            if (declaredType instanceof Class<?> objectType) {
                authObjectType = objectType.getName();
            }
        }
        System.setProperty(PROP_MODE, mode.name());
        System.setProperty(PROP_AUTH_OBJECT_LOCATION, authObjectLocation.name());
        System.setProperty(PROP_AUTH_OBJECT_ATTRIBUTE, authObjectAttribute != null ? authObjectAttribute : "");
        System.setProperty(PROP_AUTH_OBJECT_TYPE, authObjectType != null ? authObjectType : Object.class.getName());
        return new String[]{ AI_SECURITY_CONFIGURATION };
    }
}
