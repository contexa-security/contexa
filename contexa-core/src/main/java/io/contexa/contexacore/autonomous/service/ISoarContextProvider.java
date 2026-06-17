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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.domain.entity.ThreatIndicator;

import java.util.List;
import java.util.Map;

public interface ISoarContextProvider {

    SoarContext createContextFromEvents(List<SecurityEvent> events);

    SoarContext createContextFromThreatIndicators(List<ThreatIndicator> indicators);

    SoarContext enrichContext(SoarContext context, Map<String, Object> additionalInfo);

    SoarContext createEmergencyContext(String description, String severity);
}
