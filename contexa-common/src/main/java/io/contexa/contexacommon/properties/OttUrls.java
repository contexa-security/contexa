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
package io.contexa.contexacommon.properties;

import lombok.Data;


@Data
public class OttUrls {
    

    
    private String requestCodeUi = "/mfa/ott/request-code-ui";

    
    private String codeGeneration = "/mfa/ott/generate-code";

    
    private String codeSent = "/mfa/ott/code-sent";

    
    private String challengeUi = "/mfa/challenge/ott";

    
    private String loginProcessing = "/login/mfa-ott";

    
    private String defaultFailure = "/mfa/challenge/ott?error=true";

    

    
    private String singleOttRequestEmail = "/loginOtt";

    
    private String singleOttCodeGeneration = "/login/ott/generate";

    
    private String singleOttChallenge = "/loginOttVerifyCode";

    
    private String singleOttSent = "/ott/sent";
}
