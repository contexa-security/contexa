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
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * Enables AI Native Zero Trust security for legacy system integration.
 * <p>
 * Place this annotation on a {@code @SpringBootApplication} class to activate
 * the Contexa AI security infrastructure. This annotation creates a default
 * {@code PlatformConfig} (if none exists) using {@code IdentityDslRegistry},
 * which triggers the full Zero Trust configurer mechanism automatically.
 *
 * <h3>Usage:</h3>
 * <pre>{@code
 * @SpringBootApplication
 * @EnableAISecurity
 * public class LegacyApplication { }
 * }</pre>
 *
 * <p>Requires {@code spring-boot-starter-security} on the classpath.
 * Legacy systems must declare this dependency explicitly.</p>
 *
 * @see Protectable
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AiSecurityImportSelector.class)
public @interface EnableAISecurity {
    /**
     * Security mode. SANDBOX is the default for legacy integration.
     */
    SecurityMode mode() default SecurityMode.SANDBOX;

    /**
     * Optional hint for authenticated object lookup in SANDBOX mode.
     */
    AuthObjectLocation authObjectLocation() default AuthObjectLocation.AUTO;

    /**
     * Optional attribute name for session/request attribute based handoff.
     */
    String authObjectAttribute() default "";

    /**
     * Optional authenticated object type hint for reflective extraction.
     */
    Class<?> authObjectType() default Object.class;
}
