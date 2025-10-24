package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.BaseAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.option.RecoveryCodeOptions;

public interface RecoveryCodeDslConfigurer extends AuthenticationFactorConfigurer<RecoveryCodeOptions, BaseAsepAttributes, RecoveryCodeDslConfigurer>  {
    RecoveryCodeDslConfigurer codeLength(int length);
    RecoveryCodeDslConfigurer numberOfCodesToGenerate(int number);
    RecoveryCodeDslConfigurer emailOtpEndpoint(String endpoint); // 추가
    RecoveryCodeDslConfigurer smsOtpEndpoint(String endpoint);   // 추가
    // order()는 AuthenticationFactorConfigurer에 이미 있음
}