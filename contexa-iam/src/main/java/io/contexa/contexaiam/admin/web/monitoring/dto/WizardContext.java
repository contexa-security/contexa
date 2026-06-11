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
package io.contexa.contexaiam.admin.web.monitoring.dto;

import lombok.Builder;

import java.io.Serializable;
import java.util.Set;

@Builder
public record WizardContext(
        String contextId,
        String sessionTitle,
        String sessionDescription,

        Subject targetSubject,
        Set<Long> initialAssignmentIds,

        Set<Long> permissionIds,

        Set<Subject> subjects

) implements Serializable {

    private static final long serialVersionUID = 4L; 

    @Builder
    public record Subject(Long id, String type) implements Serializable {
        private static final long serialVersionUID = 1L;
    }
}