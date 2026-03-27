package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.SecuritySpel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SecuritySpelRepository extends JpaRepository<SecuritySpel, Long> {

    @Query("SELECT s FROM SecuritySpel s WHERE " +
            "(:keyword IS NULL OR :keyword = '' " +
            "OR LOWER(s.name) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
            "OR LOWER(s.description) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    List<SecuritySpel> search(@Param("keyword") String keyword);
}
