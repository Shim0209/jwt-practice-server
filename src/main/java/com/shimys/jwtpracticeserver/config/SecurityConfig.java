package com.shimys.jwtpracticeserver.config;

import com.shimys.jwtpracticeserver.filter.MyFilter1;
import com.shimys.jwtpracticeserver.jwt.JwtAuthenticationFilter;
import com.shimys.jwtpracticeserver.jwt.JwtAuthorizationFilter;
import com.shimys.jwtpracticeserver.reposiroty.UserReposiroty;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsConfig corsConfig;
    private final UserReposiroty userReposiroty;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //http.addFilterBefore(new MyFilter1(), SecurityContextPersistenceFilter.class); // 스프링 필터체인보다 먼저 동작
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)// 세션 안씀
                .and()
                .addFilter(corsConfig.corsFilter()) // 모든 요청이 이 필터를 거쳐간다. crossorigin정책 안씀
                .formLogin().disable()  // 폼로그인 안씀
                .httpBasic().disable()  // 기본적인 http 로그인 안씀
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) // AuthenticationManager를 매개변수로 줘야한다.
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userReposiroty))
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }
}
