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
package io.contexa.contexaidentity.security.core.mfa.context;

import java.util.Objects;

public record FactorIdentifier(String flowName, String stepId) {

    public FactorIdentifier(String flowName, String stepId) {
        this.flowName = Objects.requireNonNull(flowName, "flowName cannot be null").toLowerCase();
        this.stepId = Objects.requireNonNull(stepId, "stepId cannot be null"); 
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FactorIdentifier that = (FactorIdentifier) o;
        return flowName.equals(that.flowName) && stepId.equals(that.stepId);
    }

    @Override
    public String toString() {
        return "FactorIdentifier{" +
                "flowName='" + flowName + '\'' +
                ", stepId='" + stepId + '\'' +
                '}';
    }

    public static FactorIdentifier of(String flowName, String stepId) {
        return new FactorIdentifier(flowName, stepId);
    }
}
