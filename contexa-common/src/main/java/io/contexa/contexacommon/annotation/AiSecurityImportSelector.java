/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.security.bridge.AuthObjectLocation;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import java.util.Map;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootVersion;
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

    public static final String PROP_MODE = "contexa.ai.security.mode";
    public static final String PROP_AUTH_OBJECT_LOCATION = "contexa.ai.security.auth-object.location";
    public static final String PROP_AUTH_OBJECT_ATTRIBUTE = "contexa.ai.security.auth-object.attribute";
    public static final String PROP_AUTH_OBJECT_TYPE = "contexa.ai.security.auth-object.type";
    private static final String AI_SECURITY_CONFIGURATION = "io.contexa.autoconfigure.ai.AiSecurityConfiguration";

    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        String version = SpringBootVersion.getVersion();
        if (version.startsWith("4.")) {
            LoggerFactory.getLogger(AiSecurityImportSelector.class)
                .error("Contexa does not support Spring Boot 4.x. Current version: {}. Please downgrade to Spring Boot 3.x.", version);
            throw new IllegalStateException("Spring Boot 4.x is not supported by Contexa. Current version: " + version);
        }

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
