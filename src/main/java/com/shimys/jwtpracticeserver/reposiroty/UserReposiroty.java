package com.shimys.jwtpracticeserver.reposiroty;

import com.shimys.jwtpracticeserver.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserReposiroty extends JpaRepository<User, Long> {
    public User findByUsername(String username);
}
