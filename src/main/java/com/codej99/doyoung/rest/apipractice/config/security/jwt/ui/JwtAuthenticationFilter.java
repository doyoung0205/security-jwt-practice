package com.codej99.doyoung.rest.apipractice.config.security.jwt.application;

import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.JwtTokenProvider;
import lombok.extern.java.Log;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Log
public class JwtAuthenticationFilter extends GenericFilterBean {
    private final JwtTokenProvider jwtTokenProvider;

    // Jwt Provier 주입
    public JwtAuthenticationFilter(final JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    // Request로 들어오는 Jwt Token의 유효성을 검증(jwtTokenProvider.validateToken)하는 filter를 filterChain에 등록합니다.
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain filterChain)
            throws IOException, ServletException {

        final String accessToken = jwtTokenProvider.resolveAccessToken((HttpServletRequest) request);
        final String refreshToken = jwtTokenProvider.resolveRefreshToken((HttpServletRequest) request);
        log.info("[JwtAuthenticationFilter.doFilter] token  ::: " + accessToken);

        if (validateJwtFilterTokens(accessToken, refreshToken)) {
            final Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }

    private boolean validateJwtFilterTokens(final String accessToken, final String refreshToken) {
        return !StringUtils.isEmpty(accessToken)
                && StringUtils.isEmpty(refreshToken)
                && jwtTokenProvider.validateAccessToken(accessToken)
                && jwtTokenProvider.validateRefreshToken(refreshToken);
    }
}


