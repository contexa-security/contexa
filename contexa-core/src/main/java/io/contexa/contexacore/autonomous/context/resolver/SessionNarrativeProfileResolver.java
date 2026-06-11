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
package io.contexa.contexacore.autonomous.context.resolver;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.SessionNarrativeProfile;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;

/**
 * Resolves SessionNarrativeProfile from metadata.
 * Extracted from DefaultCanonicalSecurityContextProvider - all business logic preserved.
 */
public class SessionNarrativeProfileResolver extends AbstractProfileResolver<SessionNarrativeProfile> {

    @Override
    protected SessionNarrativeProfile doResolve(Map<String, Object> metadata, CanonicalSecurityContext context) {
        SessionNarrativeProfile profile = SessionNarrativeProfile.builder()
                .summary(text(metadata.get("sessionNarrativeSummary")))
                .sessionAgeMinutes(toInt(metadata.get("sessionAgeMinutes"), metadata.get("sessionAge"), metadata.get("session_age_minutes")))
                .previousPath(text(metadata.get("previousPath"), metadata.get("previous_path")))
                .previousActionFamily(text(
                        metadata.get("previousActionFamily"),
                        metadata.get("previous_action_family"),
                        metadata.get("previousAction")))
                .lastRequestIntervalMs(toLong(
                        metadata.get("lastRequestIntervalMs"),
                        metadata.get("lastRequestInterval"),
                        metadata.get("last_request_interval_ms")))
                .sessionActionSequence(strings(
                        metadata.get("sessionActionSequence"),
                        metadata.get("recentSessionActions"),
                        metadata.get("sessionActions")))
                .sessionProtectableSequence(strings(
                        metadata.get("sessionProtectableSequence"),
                        metadata.get("recentProtectableSequence"),
                        metadata.get("protectableSequence")))
                .burstPattern(toBool(
                        metadata.get("burstPattern"),
                        metadata.get("requestBurstPattern"),
                        metadata.get("burstDetected")))
                .build();

        if (!StringUtils.hasText(profile.getSummary())) {
            profile.setSummary(doBuildSummary(profile, context));
        }

        return profile;
    }

    @Override
    protected boolean doHasData(SessionNarrativeProfile profile) {
        return StringUtils.hasText(profile.getSummary())
                || profile.getSessionAgeMinutes() != null
                || StringUtils.hasText(profile.getPreviousPath())
                || StringUtils.hasText(profile.getPreviousActionFamily())
                || profile.getLastRequestIntervalMs() != null
                || !profile.getSessionActionSequence().isEmpty()
                || !profile.getSessionProtectableSequence().isEmpty()
                || profile.getBurstPattern() != null;
    }

    @Override
    protected String doBuildSummary(SessionNarrativeProfile profile, CanonicalSecurityContext context) {
        List<String> facts = new ArrayList<>();
        if (profile.getSessionAgeMinutes() != null) {
            facts.add("Session age minutes: " + profile.getSessionAgeMinutes());
        }
        if (StringUtils.hasText(profile.getPreviousPath())) {
            facts.add("Previous path: " + profile.getPreviousPath());
        }
        if (StringUtils.hasText(profile.getPreviousActionFamily())) {
            facts.add("Previous action family: " + profile.getPreviousActionFamily());
        }
        if (profile.getLastRequestIntervalMs() != null) {
            facts.add("Last request interval ms: " + profile.getLastRequestIntervalMs());
        }
        if (!profile.getSessionActionSequence().isEmpty()) {
            facts.add("Session action sequence: " + String.join(", ", profile.getSessionActionSequence()));
        }
        if (!profile.getSessionProtectableSequence().isEmpty()) {
            facts.add("Protectable sequence: " + String.join(", ", profile.getSessionProtectableSequence()));
        }
        if (Boolean.TRUE.equals(profile.getBurstPattern())) {
            facts.add("Burst pattern is active");
        }
        if (facts.isEmpty() && context != null && context.getSession() != null && context.getSession().getRecentRequestCount() != null) {
            facts.add("Recent request count: " + context.getSession().getRecentRequestCount());
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    @Override
    public void apply(SessionNarrativeProfile profile, CanonicalSecurityContext context) {
        context.setSessionNarrativeProfile(profile);
    }
}
