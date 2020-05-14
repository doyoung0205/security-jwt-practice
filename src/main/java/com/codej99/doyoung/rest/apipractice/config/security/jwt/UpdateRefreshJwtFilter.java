package com.codej99.doyoung.rest.apipractice.config.security.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

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


