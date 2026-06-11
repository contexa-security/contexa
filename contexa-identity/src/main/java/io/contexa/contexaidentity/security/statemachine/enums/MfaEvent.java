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
package io.contexa.contexaidentity.security.statemachine.enums;

public enum MfaEvent {

    PRIMARY_AUTH_SUCCESS,              
    PRIMARY_AUTH_FAILURE,              

    MFA_NOT_REQUIRED,                  
    MFA_REQUIRED_SELECT_FACTOR,        

    FACTOR_SELECTED,                   
    INITIATE_CHALLENGE,                
    INITIATE_CHALLENGE_AUTO,           
    CHALLENGE_INITIATED_SUCCESSFULLY,  
    CHALLENGE_INITIATION_FAILED,       

    SUBMIT_FACTOR_CREDENTIAL,          
    FACTOR_VERIFIED_SUCCESS,           
    FACTOR_VERIFICATION_FAILED,        

    DETERMINE_NEXT_FACTOR,             
    CHECK_COMPLETION,                  

    ALL_REQUIRED_FACTORS_COMPLETED,    
    ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN, 

    USER_ABORTED_MFA,                  
    RETRY_LIMIT_EXCEEDED,              
    SESSION_TIMEOUT,                   
    CHALLENGE_TIMEOUT,                 
    SYSTEM_ERROR,                      

    AUTHENTICATION_BLOCKED,            
    RISK_LEVEL_ELEVATED,              
    ADAPTIVE_MFA_REQUIRED,            
    AI_ASSESSMENT_COMPLETED           
}