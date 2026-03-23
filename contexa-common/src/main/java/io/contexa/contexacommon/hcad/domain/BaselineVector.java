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

    
    @Builder.Default
    private Long updateCount = 0L;

    @Builder.Default
    private Map<String, Long> elementFrequencies = new HashMap<>();
    

    
    private Instant lastUpdated;          
    private Long avgRequestCount;         
    private Double avgTrustScore;         

    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    

}
