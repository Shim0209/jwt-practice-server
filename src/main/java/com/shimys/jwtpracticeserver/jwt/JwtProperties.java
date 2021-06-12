package com.shimys.jwtpracticeserver.jwt;

public interface JwtProperties {
    String NAME = "JWT_TOKEN"; // 의미없음
    String SECRET = "SHIM"; //서버만 알고있는 비밀값
    int EXPIRATION_TIME = 1000*60*10; // 10분
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
