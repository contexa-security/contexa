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
package io.contexa.contexacommon.hcad.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class BaselineVector implements Serializable {

    private static final long serialVersionUID = 1L;

    
    private String userId;

    
    private String[] normalIpRanges;      
    private Integer[] normalAccessHours;
    private Integer[] normalAccessDays;
    private String[] frequentPaths;       
    private String[] normalUserAgents;    
    private String[] normalOperatingSystems;  
    private String[] normalBrowsers;
    private String[] normalIpBands;
    private String[] normalAuthenticationTypes;
    private String[] frequentActionFamilies;
    private String[] frequentResourceFamilies;

    
    @Builder.Default
    private Long updateCount = 0L;

    @Builder.Default
    private Map<String, Long> elementFrequencies = new HashMap<>();
    

    
    private Instant lastUpdated;          
    private Long avgRequestCount;         
    private Double avgTrustScore;         

    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    

}
