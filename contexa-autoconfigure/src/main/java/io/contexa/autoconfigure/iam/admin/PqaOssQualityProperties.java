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

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The settings of the prompt quality measurement (quality plan 3.2, 3.3): the labelled cases.
 */
@ConfigurationProperties("contexa.pqa.oss.quality")
public class PqaOssQualityProperties {

    /**
     * Quality plan 3.2: whether a labelled case and each change of its answer wait until an administrator other than
     * the one who set the answer confirms it before the case enters a published set. Turn it off for an installation
     * with one administrator: cases are then confirmed as they are submitted.
     */
    private boolean twoPersonConfirmation = true;

    public boolean isTwoPersonConfirmation() {
        return twoPersonConfirmation;
    }

    public void setTwoPersonConfirmation(boolean twoPersonConfirmation) {
        this.twoPersonConfirmation = twoPersonConfirmation;
    }
}
