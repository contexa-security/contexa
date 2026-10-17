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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;

import java.time.Instant;
import java.time.ZoneId;

/**
 * The REQUEST values a v20 prompt draws from the sealed canonical context: the same functions the render uses, for
 * the prompt inspector to compare the drawn lines with the sealed sources (R1b-2), whole lines included (R1b-7). A part
 * the render may take from a source the package does not seal is a parameter the caller gives.
 */
public final class RequestLineValues {

    private RequestLineValues() {
    }

    /** {@code Wed 03:17}: the request's day and time on the event clock. */
    public static String clock(Instant at, ZoneId zone) {
        return SecurityDecisionPromptValues.requestClock(at, zone);
    }

    /** {@code 4,831 items}, or null without a requested size. */
    public static String size(Integer items) {
        return SecurityDecisionPromptValues.requestedSize(items);
    }

    /** The target's name: the path template's variables bound by the request path, else {@code resource}. */
    public static String targetHead(CanonicalSecurityContext.Resource resource) {
        return SecurityDecisionPromptValues.targetHead(resource);
    }

    /** Where the target's business label is, or null without a label: its text is an UNTRUSTED TEXT line (N-INJ-3). */
    public static String targetLabel(CanonicalSecurityContext.Resource resource) {
        return SecurityDecisionPromptValues.targetLabel(resource);
    }

    /** The device the sealed context names, or null. */
    public static String sealedDeviceName(CanonicalSecurityContext.Device device) {
        return SecurityDecisionPromptValues.sealedDeviceName(device);
    }

    /** The sealed client address, or {@code address not known}. */
    public static String address(CanonicalSecurityContext.Session session) {
        return SecurityDecisionPromptValues.networkAddress(session);
    }

    /** The subject line of the user with the account part and the sealed subject's details, or null without a user. */
    public static String subject(String userId, String account, CanonicalSecurityContext context) {
        return SecurityDecisionPromptValues.subjectLine(userId, account, context);
    }

    /** {@code account 120 days} to the time, or {@code account age not known}. */
    public static String accountAge(CanonicalSecurityContext.Actor actor, Instant at) {
        return SecurityDecisionPromptValues.accountAge(actor, at);
    }

    /** Whether the actor's account creation time reads. */
    public static boolean accountCreatedKnown(CanonicalSecurityContext.Actor actor) {
        return SecurityDecisionPromptValues.accountCreatedKnown(actor);
    }

    /** The roles line, or null without roles. */
    public static String roles(CanonicalSecurityContext context) {
        return SecurityDecisionPromptValues.rolesLine(context);
    }

    /** The permissions line, or null without permissions. */
    public static String permissions(CanonicalSecurityContext context) {
        return SecurityDecisionPromptValues.permissionsLine(context);
    }

    /** The action line of the family, its source, the method, the path, the template and the protected method. */
    public static String action(String family, String familySource, String method, String path, String template,
                                String protectedMethod) {
        return SecurityDecisionPromptValues.actionLine(family, familySource, method, path, template, protectedMethod);
    }

    /** The resource id when it names a method, or null. */
    public static String qualifiedResourceMethod(CanonicalSecurityContext.Resource resource) {
        return SecurityDecisionPromptValues.qualifiedResourceMethod(resource);
    }

    /** {@code Type.method} of a qualified method, or null. */
    public static String protectedMethod(String qualified) {
        return SecurityDecisionPromptValues.protectedMethod(qualified);
    }

    /** The resource class line, or null without a class. */
    public static String resourceClass(CanonicalSecurityContext.Resource resource) {
        return SecurityDecisionPromptValues.resourceClass(resource);
    }

    /** The network line of the sealed address with the band and the sealed location, or null. */
    public static String network(CanonicalSecurityContext.Session session, String band,
                                 CanonicalSecurityContext.Location location) {
        return SecurityDecisionPromptValues.networkLine(session, band, location);
    }

    /** The device line of a device name with whether it was seen and the sealed device's details. */
    public static String device(String name, String seen, CanonicalSecurityContext.Device device) {
        return SecurityDecisionPromptValues.deviceLine(name, seen, device);
    }

    /** Whether the device was seen, as the line states it when the host declared it or not. */
    public static String deviceSeen(boolean hostDeclared, CanonicalSecurityContext context) {
        return SecurityDecisionPromptValues.deviceSeen(hostDeclared, context);
    }
}
