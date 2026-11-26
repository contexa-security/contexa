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
package io.contexa.contexacommon.operating;

import org.springframework.context.annotation.Conditional;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Holds where the application sets nothing under any of the prefixes. Spring Boot builds some beans from the application's
 * settings (its OAuth2 client registrations, its resource server's decoder, its authorization server) only when no bean of
 * the type exists, and Contexa's auto-configurations come before Spring Boot's: a bean of Contexa's offered by type would
 * make Spring Boot leave out what the application set. Such a bean is offered only where the application set nothing of
 * the kind (R-17 of docs/agent/운영모드-정상화-구현계획.md).
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Conditional(OnNoApplicationSettingCondition.class)
public @interface ConditionalOnNoApplicationSetting {

    /** The prefixes of the settings, such as {@code spring.security.oauth2.client.registration}. */
    String[] prefix();
}
