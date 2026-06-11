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
 * {@code protectable_resource_registry}. Registered resources must obtain a
 * {@code PromptQualityCertificate} through
 * {@code EnterpriseProtectableResourceCertificationGate} before being admitted
 * to LLM zero-trust operation.
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
     * Identifier of the protected resource; unique within a tenant.
     * <p>
     * When blank, {@code ProtectableResourceCatalogService} auto-populates it
     * as {@code {className}#{methodName}}. Explicit values should follow a
     * dot-notation or kebab-case convention (for example,
     * {@code user.profile.read}).
     * <p>
     * A certificate, once issued, is bound to this identifier. Changing it
     * transitions the existing certificate to {@code EXPIRED}.
     * <p>
     * Owner: architect or security lead.
     */
    String resourceId() default "";

    /**
     * HTTP path of the protected resource. When blank the path is inferred
     * from Spring MVC annotations ({@code @RequestMapping}, {@code @GetMapping},
     * and related). When explicit the value must match the actual MVC
     * mapping; otherwise the runtime gate rejects the request with a scope
     * mismatch.
     * <p>
     * Owner: developer.
     */
    String resourceUrl() default "";

    /**
     * HTTP method of the protected resource. When blank the method is
     * inferred from MVC annotations. Allowed values: {@code GET},
     * {@code POST}, {@code PUT}, {@code PATCH}, {@code DELETE}.
     * <p>
     * The same {@code resourceId} declared under different HTTP methods
     * yields separate registry records and separate certificates.
     */
    String httpMethod() default "";

    /**
     * Criticality level of the resource.
     * <ul>
     *   <li>{@code standard} — routine business resource (default)</li>
     *   <li>{@code sensitive} — contains personal or sensitive data</li>
     *   <li>{@code critical} — core resource whose disruption impacts the business</li>
     *   <li>{@code delegated} — executed under agent delegation</li>
     * </ul>
     * <p>
     * Criticality drives certificate issuance thresholds, re-verification
     * cadence, and enforcement mode. Promotions (for example,
     * {@code standard} to {@code sensitive}) require operator approval.
     * <p>
     * Owner: architect and operator, jointly.
     */
    String criticality() default "standard";

    /**
     * Whether the certification gate must be enforced for this resource.
     * <p>
     * {@code true} (default): at invocation time
     * {@code EnterpriseProtectableResourceCertificationGate} checks for a
     * valid certificate and blocks the call when none is available.
     * <p>
     * {@code false}: the gate is skipped. Reserved for exceptional cases
     * such as authentication primitives or health checks, and requires audit
     * approval with an explicit reason.
     */
    boolean verificationRequired() default true;

    /**
     * Whether the LLM decision must be executed synchronously.
     * <p>
     * {@code true}: at invocation time
     * {@code SynchronousProtectableDecisionService.analyze()} runs the full
     * pipeline — {@code ZeroTrustSpringEvent} assembly,
     * {@code SecurityPlaneAgent} processing, and decision resolution — before
     * the call returns, guaranteeing decision finality in the response.
     * <p>
     * {@code false} (default): the event is published and the decision runs
     * asynchronously, favoring response latency.
     * <p>
     * Owner: architect and performance team, jointly. Recommended only for
     * {@code criticality=critical} resources whose response can be delivered
     * within the 3-second SLA.
     */
    boolean sync() default false;
}
