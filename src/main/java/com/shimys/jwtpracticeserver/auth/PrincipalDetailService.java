package com.shimys.jwtpracticeserver.auth;

import com.shimys.jwtpracticeserver.model.User;
import com.shimys.jwtpracticeserver.reposiroty.UserReposiroty;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080//login => 여기서 동작을 안함. SecurityConfig에서 formlogin.disable했기때문에
@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {

    private final UserReposiroty userReposiroty;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailService의 loadUserByUsername()");
        User userEntity = userReposiroty.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
}
