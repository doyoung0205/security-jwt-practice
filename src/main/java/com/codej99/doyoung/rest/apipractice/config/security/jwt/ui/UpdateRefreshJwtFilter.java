package com.codej99.doyoung.rest.apipractice.config.security.jwt.application;

import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;


// TODO 어떤 요청이 왔을 때 무사히 끝났으면,
// TODO refreshToken 이 있는 지 검사하고 있으면 유효 기간을 다시 초기화 시켜주는 작업이 필요하다.

@Log
@RequiredArgsConstructor
public class UpdateRefreshJwtFilter extends GenericFilterBean {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        // TODO refresh Token 기간 연장 !!
        log.info("[UpdateRefreshJwtFilter.doFilter] token  실행");
        filterChain.doFilter(request, response);
    }
}