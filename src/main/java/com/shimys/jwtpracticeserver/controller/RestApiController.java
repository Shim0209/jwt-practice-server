package com.shimys.jwtpracticeserver.controller;

import com.shimys.jwtpracticeserver.model.User;
import com.shimys.jwtpracticeserver.reposiroty.UserReposiroty;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

//@CrossOrigin => 인증이 필요없는 요청만 가능하다. 인증이 필요한 요청은 거부된다. => CorsConfig에서 설정
@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserReposiroty userReposiroty;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userReposiroty.save(user);
        return "회원가입완료";
    }

    // user, manager, admin 권한만 접근가능
    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }

    // manager, admin 권한만 접근가능
    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }

    // admin 권한만 접근가능
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
