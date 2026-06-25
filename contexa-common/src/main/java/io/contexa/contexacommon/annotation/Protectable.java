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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares a resource as protected by the Contexa zero-trust framework.
 * <p>
 * At application startup {@code ProtectableResourceCatalogService} auto-scans
 * annotated beans and registers matching methods into
 * {@code protectable_resource_registry}. Registered resources can be evaluated
 * by the prompt quality inspection flow before they are used for LLM
 * zero-trust operation. Enterprise deployments may add certificate and
 * promotion gates on top of that inspection result.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Protectable {

    /**
     * Field or getter property name on the target object used for row-level
     * ownership verification.
     * <p>
     * When blank, no ownership check is performed. When set,
     * {@code CustomMethodSecurityExpressionRoot.checkOwnership()} compares the
     * value of the named field on the target against the authenticated user
     * name (administrators bypass this check).
     * <p>
     * Owner: domain developer.
     */
    String ownerField() default "";

    /**
     * Whether prompt quality verification must be enforced for this resource.
     * <p>
     * {@code true} (default): at invocation time the runtime policy checks
     * whether the resource has the required prompt quality state.
     * <p>
     * {@code false}: the verification gate is skipped. Reserved for exceptional
     * cases such as authentication primitives or health checks.
     */
    boolean verificationRequired() default true;

    /**
     * Whether the LLM decision must be executed synchronously.
     * <p>
     * {@code true}: at invocation time
     * {@code SynchronousProtectableDecisionService.analyze()} runs the full
     * pipeline before the call returns, guaranteeing decision finality in the
     * response.
     * <p>
     * {@code false} (default): the event is published and the decision runs
     * asynchronously, favoring response latency.
     * <p>
     * Owner: architect and performance team, jointly. Recommended only for
     * resources whose response can be delivered within the 3-second SLA.
     */
    boolean sync() default false;
}
