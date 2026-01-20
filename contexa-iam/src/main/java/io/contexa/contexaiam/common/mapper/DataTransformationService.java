package io.contexa.contexaiam.common.mapper;

import java.util.List;


public interface DataTransformationService {
    
    <T, D> D toDto(T entity, Class<D> dtoClass);

    
    <T, D> List<D> toDtoList(List<T> entityList, Class<D> dtoClass);

    
    <D, T> T toEntity(D dto, Class<T> entityClass);
}
