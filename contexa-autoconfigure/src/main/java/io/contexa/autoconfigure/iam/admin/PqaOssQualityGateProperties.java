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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.std.components.prompt.quality.QualityGateMode;
import io.contexa.contexacore.std.components.prompt.quality.QualityGatePolicy;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Plan 3.4, 5 step 5: the quality gate the release gate applies when a version of the security decision is used for
 * decisions or started as a canary. It goes in as a warning; an installation blocks with it once the reproducibility
 * and discrimination checks of plan 6 have passed. A value outside its range stops the start.
 */
@ConfigurationProperties("contexa.pqa.oss.quality.gate")
public class PqaOssQualityGateProperties {

    private static final QualityGateSettings DEFAULTS = QualityGateSettings.defaults();

    /** WARN applies a blocked verdict as a warning (the default); BLOCK blocks, and a reason overrides it. */
    private QualityGateMode mode = QualityGateMode.WARN;

    /** The largest share of answers decided without the model. */
    private double modelLessLimit = DEFAULTS.modelLessLimit();

    /** The level of the exact tests that say a rate grew. */
    private double significance = DEFAULTS.significance();

    /** The distinct roots of cases that must be stopped needed to tell two versions apart. */
    private int minimumStopRoots = DEFAULTS.minimumStopRoots();

    /** The distinct roots of cases that must be allowed needed to tell two versions apart. */
    private int minimumAllowRoots = DEFAULTS.minimumAllowRoots();

    /** The quality gate with the measurements of the source, these thresholds and this mode. */
    public QualityGatePolicy policy(QualityGateSource source) {
        return new QualityGatePolicy(source, mode,
                new QualityGateSettings(modelLessLimit, significance, minimumStopRoots, minimumAllowRoots));
    }

    public QualityGateMode getMode() {
        return mode;
    }

    public void setMode(QualityGateMode mode) {
        this.mode = mode;
    }

    public double getModelLessLimit() {
        return modelLessLimit;
    }

    public void setModelLessLimit(double modelLessLimit) {
        this.modelLessLimit = modelLessLimit;
    }

    public double getSignificance() {
        return significance;
    }

    public void setSignificance(double significance) {
        this.significance = significance;
    }

    public int getMinimumStopRoots() {
        return minimumStopRoots;
    }

    public void setMinimumStopRoots(int minimumStopRoots) {
        this.minimumStopRoots = minimumStopRoots;
    }

    public int getMinimumAllowRoots() {
        return minimumAllowRoots;
    }

    public void setMinimumAllowRoots(int minimumAllowRoots) {
        this.minimumAllowRoots = minimumAllowRoots;
    }
}
