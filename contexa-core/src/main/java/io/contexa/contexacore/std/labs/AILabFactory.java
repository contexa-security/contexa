package io.contexa.contexacore.std.labs;

import java.util.Optional;

/**
 * AI Lab 팩토리 인터페이스
 *
 * Lab 인스턴스의 생성과 조회를 담당하는 팩토리 패턴 구현
 * LabAccessor의 기능을 표준화하고 확장
 */
public interface AILabFactory {

    /**
     * 타입으로 Lab을 조회
     * 기존 LabAccessor.getLab()과 동일
     *
     * @param labType Lab 타입 클래스
     * @return Lab 인스턴스 (Optional)
     */
    <T extends AILab<?, ?>> Optional<T> getLab(Class<T> labType);

    /**
     * 새로운 Lab 인스턴스 생성
     *
     * @param labType Lab 타입 클래스
     * @return 새로운 Lab 인스턴스
     * @throws UnsupportedOperationException 지원하지 않는 Lab 타입인 경우
     */
    <T extends AILab<?, ?>> T createLab(Class<T> labType);

    /**
     * 클래스 이름으로 Lab을 조회
     * 기존 LabAccessor.getLabByClassName()과 동일
     *
     * @param className 클래스 이름
     * @return Lab 인스턴스 (Optional)
     */
    Optional<AILab<?, ?>> getLabByClassName(String className);

    /**
     * Lab 존재 여부 확인
     *
     * @param labType Lab 타입
     * @return 존재 여부
     */
    default boolean hasLab(Class<? extends AILab<?, ?>> labType) {
        return getLab(labType).isPresent();
    }

    /**
     * 클래스 이름으로 Lab 존재 여부 확인
     *
     * @param className 클래스 이름
     * @return 존재 여부
     */
    default boolean hasLab(String className) {
        return getLabByClassName(className).isPresent();
    }
}
