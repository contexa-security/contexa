package io.contexa.contexacommon.properties;

import lombok.Data;
import org.springframework.boot.context.properties.NestedConfigurationProperty;


@Data
public class AuthUrlConfig {

    
    @NestedConfigurationProperty
    private SingleAuthUrls single = new SingleAuthUrls();

    
    @NestedConfigurationProperty
    private PrimaryAuthUrls primary = new PrimaryAuthUrls();

    
    @NestedConfigurationProperty
    private MfaUrls mfa = new MfaUrls();

    
    @NestedConfigurationProperty
    private FactorUrls factors = new FactorUrls();
}
