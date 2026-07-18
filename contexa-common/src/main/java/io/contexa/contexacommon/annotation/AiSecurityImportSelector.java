/* Copyright 2026 The Contexa Project */
package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.security.bridge.AuthObjectLocation;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootVersion;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.type.AnnotationMetadata;

import java.util.LinkedHashMap;
import java.util.Map;

/** Loads the Contexa configuration and publishes annotation values into this context's Environment. */
public class AiSecurityImportSelector implements ImportSelector, EnvironmentAware {

    public static final String PROP_ENABLED = "contexa.enabled";
    public static final String PROP_MODE = "contexa.ai.security.mode";
    public static final String PROP_AUTH_OBJECT_LOCATION = "contexa.ai.security.auth-object.location";
    public static final String PROP_AUTH_OBJECT_ATTRIBUTE = "contexa.ai.security.auth-object.attribute";
    public static final String PROP_AUTH_OBJECT_TYPE = "contexa.ai.security.auth-object.type";
    public static final String PROP_BRIDGE_OWNERSHIP = "contexa.bridge.ownership";
    public static final String PROP_CONTEXA_OWNED_APPLICATION =
            "contexa.datasource.isolation.contexa-owned-application";
    private static final String AI_SECURITY_CONFIGURATION = "io.contexa.autoconfigure.ai.AiSecurityConfiguration";
    private ConfigurableEnvironment environment;

    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        if (environment != null && !environment.getProperty(PROP_ENABLED, Boolean.class, true)) {
            return new String[0];
        }

        String version = SpringBootVersion.getVersion();
        if (version.startsWith("4.")) {
            LoggerFactory.getLogger(AiSecurityImportSelector.class)
                    .error("Contexa does not support Spring Boot 4.x. Current version: {}. Please downgrade to Spring Boot 3.x.", version);
            throw new IllegalStateException("Spring Boot 4.x is not supported by Contexa. Current version: " + version);
        }

        Map<String, Object> attributes = importingClassMetadata
                .getAnnotationAttributes(EnableAISecurity.class.getName(), false);
        SecurityMode mode = SecurityMode.SANDBOX;
        AuthObjectLocation location = AuthObjectLocation.AUTO;
        String attribute = "";
        String type = Object.class.getName();
        if (attributes != null) {
            if (attributes.get("mode") instanceof SecurityMode declaredMode) {
                mode = declaredMode;
            }
            if (attributes.get("authObjectLocation") instanceof AuthObjectLocation declaredLocation) {
                location = declaredLocation;
            }
            if (attributes.get("authObjectAttribute") instanceof String declaredAttribute) {
                attribute = declaredAttribute;
            }
            if (attributes.get("authObjectType") instanceof Class<?> declaredType) {
                type = declaredType.getName();
            }
        }

        Map<String, Object> activation = new LinkedHashMap<>();
        activation.put(PROP_MODE, mode.name());
        activation.put(PROP_AUTH_OBJECT_LOCATION, location.name());
        activation.put(PROP_AUTH_OBJECT_ATTRIBUTE, attribute != null ? attribute : "");
        activation.put(PROP_AUTH_OBJECT_TYPE, type != null ? type : Object.class.getName());
        if (environment == null || !environment.containsProperty(PROP_BRIDGE_OWNERSHIP)) {
            activation.put(PROP_BRIDGE_OWNERSHIP,
                    mode == SecurityMode.FULL
                            ? SecurityOwnershipMode.CONTEXA_OWNED.name()
                            : SecurityOwnershipMode.HOST_OWNED.name());
        }
        if (environment == null || !environment.containsProperty(PROP_CONTEXA_OWNED_APPLICATION)) {
            activation.put(PROP_CONTEXA_OWNED_APPLICATION, mode == SecurityMode.FULL);
        }
        if (environment != null) {
            environment.getPropertySources().addFirst(
                    new MapPropertySource("contexaAiSecurityAnnotation", activation));
        }
        return new String[]{AI_SECURITY_CONFIGURATION};
    }

    @Override
    public void setEnvironment(Environment environment) {
        if (environment instanceof ConfigurableEnvironment configurableEnvironment) {
            this.environment = configurableEnvironment;
        }
    }
}
