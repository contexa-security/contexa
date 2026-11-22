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
package io.contexa.contexacore.std.components.prompt.quality;

/**
 * The thresholds of the quality gate (plan 3.4); an installation can change each.
 *
 * @param modelLessLimit        the largest share of answers decided without the model, such as 0.05
 * @param significance          the level of the exact tests, such as 0.05
 * @param minimumStopRoots      how many distinct roots of cases that must be stopped are needed to tell versions
 *                              apart
 * @param minimumAllowRoots     how many distinct roots of cases that must be allowed are needed
 * @param frictionIncreaseLimit how far the friction may grow over the version in use, as a difference of the two
 *                              rates (0.30 is 30 percentage points), before the gate blocks whatever the
 *                              significance; above 0 and at most 1
 */
public record QualityGateSettings(double modelLessLimit, double significance, int minimumStopRoots,
                                  int minimumAllowRoots, double frictionIncreaseLimit) {

    public QualityGateSettings {
        if (!(modelLessLimit >= 0 && modelLessLimit <= 1)) {
            throw new IllegalArgumentException("The limit of answers decided without the model is a share: "
                    + modelLessLimit);
        }
        if (!(significance > 0 && significance < 1)) {
            throw new IllegalArgumentException("The significance level lies between 0 and 1: " + significance);
        }
        if (minimumStopRoots < 0 || minimumAllowRoots < 0) {
            throw new IllegalArgumentException("The needed roots cannot be negative");
        }
        if (!(frictionIncreaseLimit > 0 && frictionIncreaseLimit <= 1)) {
            throw new IllegalArgumentException("The limit of the friction increase is a difference of two rates above 0"
                    + " and at most 1: " + frictionIncreaseLimit);
        }
    }

    /**
     * The defaults of the plan: 5% decided without the model, the 5% level, and 200 and 300 distinct roots (plan 3.2);
     * and a friction that grows by 30 percentage points or more blocks (quality P8).
     */
    public static QualityGateSettings defaults() {
        return new QualityGateSettings(0.05, 0.05, 200, 300, 0.30);
    }
}
