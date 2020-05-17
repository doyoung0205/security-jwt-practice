package com.codej99.doyoung.rest.apipractice.config.security.jwt.ui;

import com.codej99.doyoung.rest.apipractice.config.security.jwt.application.JwtTokenService;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.application.JwtTokenServiceImpl;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtTokenUtil;
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
    private final JwtTokenService jwtTokenService;

    // Jwt Provier 주입
    public JwtAuthenticationFilter(final JwtTokenServiceImpl jwtTokenService) {
        this.jwtTokenService = jwtTokenService;
    }

    // Request로 들어오는 Jwt Token의 유효성을 검증(jwtTokenProvider.validateToken)하는 filter를 filterChain에 등록합니다.
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain filterChain)
            throws IOException, ServletException {

        final String accessToken = JwtTokenUtil.getRequestAcessToken((HttpServletRequest) request);
        final String refreshToken = JwtTokenUtil.getRequestRefreshToken((HttpServletRequest) request);
        log.info("[JwtAuthenticationFilter.doFilter] token  ::: " + accessToken);

        if (validateJwtFilterTokens(accessToken, refreshToken)) {
            final Authentication authentication = jwtTokenService.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }

    // TOKEN 권한이 필요한 요청이 들어왔을때, 유효성 검사
    private boolean validateJwtFilterTokens(final String accessToken, final String refreshToken) {
        return !StringUtils.isEmpty(accessToken)
                && StringUtils.isEmpty(refreshToken)
                // Acess Token 이 구성이 잘못되어있는지, expired 된 토큰인지, 로그아웃 한 토큰인지,
                && jwtTokenService.validateAccessToken(accessToken)
                // 만약에 refresh token 이 있다면
                // token 이 구성이 잘못되어있는지, expired 되었는지,
                && jwtTokenService.validateRefreshToken(refreshToken);
    }
}


