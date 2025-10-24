package io.contexa.contexaiam.common.mapper;

import java.util.List;

/**
 * <strong>[유지]</strong> 데이터 변환 서비스 (Data Transformation Service)<br>
 * 엔티티와 DTO 간의 변환을 전담합니다. 이 인터페이스는 명칭과 역할이 적절하므로 그대로 유지합니다.
 * 내부적으로 ModelMapper 등을 사용하여 반복적인 변환 로직을 캡슐화합니다.
 */
public interface DataTransformationService {
    /**
     * 단일 엔티티를 지정된 DTO 클래스로 변환합니다.
     * @param entity 변환할 엔티티 객체
     * @param dtoClass 변환될 DTO의 클래스 타입
     * @return 변환된 DTO 객체
     */
    <T, D> D toDto(T entity, Class<D> dtoClass);

    /**
     * 엔티티 목록을 DTO 목록으로 일괄 변환합니다.
     * @param entityList 변환할 엔티티 목록
     * @param dtoClass 변환될 DTO의 클래스 타입
     * @return 변환된 DTO 목록
     */
    <T, D> List<D> toDtoList(List<T> entityList, Class<D> dtoClass);

    /**
     * 단일 DTO를 지정된 엔티티 클래스로 변환합니다.
     * @param dto 변환할 DTO 객체
     * @param entityClass 변환될 엔티티의 클래스 타입
     * @return 변환된 엔티티 객체
     */
    <D, T> T toEntity(D dto, Class<T> entityClass);
}
