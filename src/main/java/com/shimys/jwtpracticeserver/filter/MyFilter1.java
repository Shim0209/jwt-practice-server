package com.shimys.jwtpracticeserver.filter;


import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;


public class MyFilter1 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        // POST 요청만
        if (req.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            // Hello 토큰일 경우에만 컨트롤러 접근허용
            if (headerAuth.equals("Hello")){
                System.out.println("필터1");
                filterChain.doFilter(req, res);
            } else { // Hello 토큰이 아닌경우 필터체인 실행 안되도록 차단
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }
    }
}
