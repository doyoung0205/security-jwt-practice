package com.codej99.doyoung.rest.apipractice.repo;

import com.codej99.doyoung.rest.apipractice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserJpaRepo extends JpaRepository<User, Long> {
    Optional<User> findByUid(String email);
}
