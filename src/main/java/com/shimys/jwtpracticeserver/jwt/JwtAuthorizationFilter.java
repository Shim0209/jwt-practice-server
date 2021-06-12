package com.shimys.jwtpracticeserver.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.shimys.jwtpracticeserver.auth.PrincipalDetails;
import com.shimys.jwtpracticeserver.model.User;
import com.shimys.jwtpracticeserver.reposiroty.UserReposiroty;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티의 BasicAuthenticationFilter는
// 권한이나 인증이 필요한 특정 주소를 요청시 거쳐야 한다.
// 권한이나 인증이 필요한 주소가 아니라면 해당 필터를 거치지 않는다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserReposiroty userReposiroty;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserReposiroty userReposiroty) {
        super(authenticationManager);
        this.userReposiroty = userReposiroty;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소가 요청이 됨.");

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);

        if(jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");

        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
                .build().verify(jwtToken).getClaim("username").asString();

        // 서명이 정상적으로 됨
        if(username != null) {
           User userEntity = userReposiroty.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities()); // UserDetail, password, authorities

            // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장한다.
            // 궁금한거 -> 시큐리티 세션 속 Authentication객체는 요청이 끝나면 사라지는가?
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 인증 후 다음으로 넘긴다.
            chain.doFilter(request, response);
        }
    }
}
