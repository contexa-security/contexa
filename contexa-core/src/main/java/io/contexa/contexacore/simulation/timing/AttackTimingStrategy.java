package io.contexa.contexacore.simulation.timing;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Random;
import java.util.concurrent.TimeUnit;

/**
 * 공격 패턴별 현실적인 시간 지연 전략
 *
 * 실제 공격 패턴을 시뮬레이션하기 위해 각 공격 유형에 맞는
 * 현실적인 시간 지연을 적용합니다. 테스트를 위해 초 단위로 조정되었습니다.
 */
@Slf4j
@Component
public class AttackTimingStrategy {

    private final Random random = new Random();

    /**
     * 공격 패턴에 따른 지연 시간 계산
     */
    public void applyDelay(AttackPattern pattern) {
        long delayMs = calculateDelay(pattern);
        if (delayMs > 0) {
            try {
                log.debug("공격 패턴 {} 지연: {}ms", pattern, delayMs);
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.warn("공격 지연 중단됨", e);
            }
        }
    }

    /**
     * 공격 간 지연 시간 적용 (액션 간 지연)
     */
    public void applyActionDelay(AttackPattern pattern, int actionIndex) {
        long delayMs = calculateActionDelay(pattern, actionIndex);
        if (delayMs > 0) {
            try {
                log.debug("액션 {} 지연: {}ms (패턴: {})", actionIndex, delayMs, pattern);
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.warn("액션 지연 중단됨", e);
            }
        }
    }

    /**
     * 공격 패턴별 기본 지연 시간 계산 (밀리초)
     */
    private long calculateDelay(AttackPattern pattern) {
        return switch (pattern) {
            // STEALTH: 은밀한 공격 - 느리고 조심스러운 패턴 (3-10초 간격)
            case STEALTH -> 3000 + random.nextInt(7000);

            // BURST: 집중 공격 - 빠른 연속 공격 (0.1-0.5초 간격)
            case BURST -> 100 + random.nextInt(400);

            // DISTRIBUTED: 분산 공격 - 여러 소스에서 불규칙한 간격 (2-8초)
            case DISTRIBUTED -> 2000 + random.nextInt(6000);

            // TIME_BASED: 시간 기반 공격 - 특정 시간대에 집중 (1-3초)
            case TIME_BASED -> 1000 + random.nextInt(2000);

            // ADAPTIVE: 적응형 공격 - 탐지 회피를 위한 가변 간격 (0.5-5초)
            case ADAPTIVE -> 500 + random.nextInt(4500);

            // RECONNAISSANCE: 정찰 - 매우 느린 탐색 (5-15초)
            case RECONNAISSANCE -> 5000 + random.nextInt(10000);

            // EXPLOITATION: 취약점 공격 - 중간 속도 (1-4초)
            case EXPLOITATION -> 1000 + random.nextInt(3000);

            // PERSISTENCE: 지속성 확보 - 느린 속도 (3-8초)
            case PERSISTENCE -> 3000 + random.nextInt(5000);

            // LATERAL_MOVEMENT: 수평 이동 - 조심스러운 이동 (4-10초)
            case LATERAL_MOVEMENT -> 4000 + random.nextInt(6000);

            // EXFILTRATION: 데이터 유출 - 탐지 회피를 위한 느린 속도 (2-6초)
            case EXFILTRATION -> 2000 + random.nextInt(4000);

            // NORMAL: 일반 활동 시뮬레이션 (0.5-2초)
            case NORMAL -> 500 + random.nextInt(1500);

            default -> 1000; // 기본값 1초
        };
    }

    /**
     * 액션별 세부 지연 시간 계산
     */
    private long calculateActionDelay(AttackPattern pattern, int actionIndex) {
        // 첫 액션은 즉시 실행
        if (actionIndex == 0) {
            return 0;
        }

        return switch (pattern) {
            // STEALTH: 액션마다 점진적으로 느려짐 (은밀성 증가)
            case STEALTH -> {
                long base = 2000 + (actionIndex * 500);
                yield base + random.nextInt(2000);
            }

            // BURST: 초반 빠르고 후반 느림 (피로 공격 패턴)
            case BURST -> {
                if (actionIndex < 5) {
                    yield 50 + random.nextInt(100); // 초반: 매우 빠름
                } else {
                    yield 500 + random.nextInt(1000); // 후반: 느려짐
                }
            }

            // DISTRIBUTED: 불규칙한 패턴
            case DISTRIBUTED -> {
                if (random.nextBoolean()) {
                    yield 100 + random.nextInt(500); // 짧은 간격
                } else {
                    yield 3000 + random.nextInt(5000); // 긴 간격
                }
            }

            // TIME_BASED: 특정 시간대 시뮬레이션
            case TIME_BASED -> {
                // 업무 시간 시뮬레이션: 빠른 액션
                if (actionIndex % 10 < 7) {
                    yield 500 + random.nextInt(1000);
                } else {
                    // 비업무 시간: 느린 액션
                    yield 3000 + random.nextInt(5000);
                }
            }

            // ADAPTIVE: 탐지 시스템 반응에 따라 조정
            case ADAPTIVE -> {
                // 초반: 빠름 -> 중반: 느림 -> 후반: 다시 빠름
                if (actionIndex < 3) {
                    yield 200 + random.nextInt(500);
                } else if (actionIndex < 8) {
                    yield 2000 + random.nextInt(3000);
                } else {
                    yield 500 + random.nextInt(1000);
                }
            }

            // RECONNAISSANCE: 매우 조심스러운 탐색
            case RECONNAISSANCE -> {
                // 점진적으로 빨라짐 (신뢰도 증가 시뮬레이션)
                long base = Math.max(1000, 5000 - (actionIndex * 300));
                yield base + random.nextInt(2000);
            }

            // EXPLOITATION: 성공 후 빨라지는 패턴
            case EXPLOITATION -> {
                if (actionIndex < 2) {
                    yield 2000 + random.nextInt(2000); // 초반: 조심스럽게
                } else {
                    yield 500 + random.nextInt(1000); // 성공 후: 빠르게
                }
            }

            // PERSISTENCE: 일정한 간격
            case PERSISTENCE -> 3000 + random.nextInt(2000);

            // LATERAL_MOVEMENT: 단계별로 느려지는 패턴
            case LATERAL_MOVEMENT -> {
                long base = 2000 * (1 + actionIndex / 3);
                yield base + random.nextInt(3000);
            }

            // EXFILTRATION: 점진적으로 빨라지다가 마지막에 느려짐
            case EXFILTRATION -> {
                if (actionIndex < 5) {
                    yield Math.max(500, 3000 - (actionIndex * 400));
                } else {
                    yield 4000 + random.nextInt(3000);
                }
            }

            // NORMAL: 일반적인 사용자 행동
            case NORMAL -> 1000 + random.nextInt(2000);

            default -> 1000;
        };
    }

    /**
     * 공격 시작 전 초기 지연 (정찰 단계)
     */
    public void applyInitialDelay(AttackPattern pattern) {
        long delayMs = switch (pattern) {
            case STEALTH, RECONNAISSANCE -> 5000 + random.nextInt(5000);
            case DISTRIBUTED -> 2000 + random.nextInt(3000);
            case ADAPTIVE -> 1000 + random.nextInt(2000);
            default -> random.nextInt(1000);
        };

        if (delayMs > 0) {
            try {
                log.info("공격 시작 전 초기 지연: {}ms (패턴: {})", delayMs, pattern);
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 공격 종료 후 지연 (흔적 제거 시뮬레이션)
     */
    public void applyFinalDelay(AttackPattern pattern) {
        long delayMs = switch (pattern) {
            case STEALTH -> 3000 + random.nextInt(5000);
            case PERSISTENCE -> 5000 + random.nextInt(5000);
            case EXFILTRATION -> 2000 + random.nextInt(3000);
            default -> random.nextInt(2000);
        };

        if (delayMs > 0) {
            try {
                log.debug("공격 종료 후 지연: {}ms (패턴: {})", delayMs, pattern);
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 공격 패턴 열거형
     */
    public enum AttackPattern {
        STEALTH,           // 은밀한 공격
        BURST,             // 집중 공격
        DISTRIBUTED,       // 분산 공격
        TIME_BASED,        // 시간 기반 공격
        ADAPTIVE,          // 적응형 공격
        RECONNAISSANCE,    // 정찰
        EXPLOITATION,      // 취약점 공격
        PERSISTENCE,       // 지속성 확보
        LATERAL_MOVEMENT,  // 수평 이동
        EXFILTRATION,      // 데이터 유출
        NORMAL            // 일반 활동
    }
}