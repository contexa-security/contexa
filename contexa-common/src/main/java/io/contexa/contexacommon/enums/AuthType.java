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
package io.contexa.contexacommon.enums;


public enum AuthType {
    FORM(false),
    REST(false),

    
    PASSKEY(false),      
    OTT(true),           
    RECOVERY_CODE(true), 

    
    MFA(false),
    MFA_FORM(false),
    MFA_REST(false),
    MFA_OTT(false),
    MFA_PASSKEY(false),
    PRIMARY(false);

    
    private final boolean allowChallengeReuse;

    AuthType(boolean allowChallengeReuse) {
        this.allowChallengeReuse = allowChallengeReuse;
    }

    
    public boolean isAllowChallengeReuse() {
        return allowChallengeReuse;
    }
}
