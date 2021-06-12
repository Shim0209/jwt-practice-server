package com.shimys.jwtpracticeserver.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.shimys.jwtpracticeserver.auth.PrincipalDetails;
import com.shimys.jwtpracticeserver.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * 기본적으로
 * 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
 * /login 요청해서 username, password 전송하면 (post)
 * UsernamePasswordAuthenticationFilter 동작을 함.
 *
 * SecurityConfig에서 formLogin().disable() 했기때문에
 * 위의 필터가 동작을 안함.
 *
 * 따라서
 * 해당 필터를 구현한 JwtAuthenticationFilter를
 * 시큐리티 필터체인에 등록시켜줘야함.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        // 1. username, password 받아서
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 2. 정상적인지 로그인 시도
            // authenticationManager로 로그인 시도
            // PrincipalDetailsService의 loadUSerByUsername() 호출.
            // 정상이면 authentication이 리텀됨.
            // 즉, 인증이 되었다는뜻.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 3. Principal Details를 세션에 저장 (권한관리를 위해서)
            // return 될때 authentication 객체가 session 영역에 저장됨. // 로그인 완료
            // 스프링 시큐리티 세션에 담아주어야 시큐리티에서 권한관리가 된다.
            // 완전한 stateless한 JWT 서버를 구축하려면 로그인, 권한관리 로직을 따로 만들어야 한다.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다.
    // JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해준다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻임.");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식 아님 => HASH 암호방식
        String jwtToken = JWT.create()
                .withSubject(JwtProperties.NAME) // 토큰 이름 (의미없음)
                .withExpiresAt(new Date(System.currentTimeMillis()+(JwtProperties.EXPIRATION_TIME))) // 유효시간 설정
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));  // 내 서버만 아는 고유한 값

        // 클라이언트에 응답할 헤더에 토큰 담기
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
    }
}
