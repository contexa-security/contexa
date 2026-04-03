package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.SecuritySpel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SecuritySpelRepository extends JpaRepository<SecuritySpel, Long> {

    @Query("SELECT s FROM SecuritySpel s WHERE " +
            "(:pattern IS NULL " +
            "OR LOWER(s.name) LIKE :pattern " +
            "OR LOWER(s.description) LIKE :pattern)")
    List<SecuritySpel> search(@Param("pattern") String pattern);
}
