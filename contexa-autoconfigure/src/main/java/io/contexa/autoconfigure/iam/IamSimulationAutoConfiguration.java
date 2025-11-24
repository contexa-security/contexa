package io.contexa.autoconfigure.iam;

import io.contexa.contexaiam.aiam.config.SimulationWebConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

/**
 * IAM Simulation AutoConfiguration
 *
 * 시뮬레이션 인터셉터 설정
 */
@AutoConfiguration
@Import(SimulationWebConfig.class)
public class IamSimulationAutoConfiguration {
}
