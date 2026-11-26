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

import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.context.annotation.Conditional;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The mode the application runs Contexa in, read as {@link ContexaOperatingProfile} reads it: whether Contexa's main chain
 * signs the application's users in (FULL) or Contexa is kept apart from them (SANDBOX).
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Conditional(OnModeCondition.class)
public @interface ConditionalOnMode {

    SecurityMode value();

    /** Whether this also holds where no mode is declared at all, as in an application where Contexa is dormant. */
    boolean matchIfUndeclared() default false;
}
