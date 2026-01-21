package com.alnaseem.jwt.repositories;

import com.alnaseem.jwt.entities.JwtToken;
import com.alnaseem.jwt.entities.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<JwtToken, Long> {
    @Modifying
    @Transactional
    @Query("UPDATE JwtToken t SET t.active = false WHERE t.token = :token")
    void softDeleteByToken(String token);

    Optional<JwtToken> findByToken(String token);

    @Modifying
    @Transactional
    @Query("UPDATE JwtToken t SET t.active = false WHERE t.username = :username")
    void softDeleteByUsername(@Param("username") String username);

    @Modifying
    @Transactional
    @Query("UPDATE JwtToken t SET t.active = false WHERE t.username = :username AND t.type = :type")
    void softDeleteByTypeAndUsername(@Param("type") TokenType type, @Param("username") String username);
}
