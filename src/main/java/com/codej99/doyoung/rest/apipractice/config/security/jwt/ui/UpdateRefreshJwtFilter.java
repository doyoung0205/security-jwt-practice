package com.codej99.doyoung.rest.apipractice.config.security.jwt.ui;

import com.codej99.doyoung.rest.apipractice.config.security.jwt.application.JwtTokenServiceImpl;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.infra.model.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


//  어떤 요청이 왔을 때 무사히 끝났으면,
// refreshToken 이 있는 지 검사하고 있으면 유효 기간을 다시 초기화 시켜주는 작업이 필요하다.

@Log
@RequiredArgsConstructor
public class UpdateRefreshJwtFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtTokenServiceImpl jwtTokenService;

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("[UpdateRefreshJwtFilter.successfulAuthentication] 실행");

        log.info("authResult ::: " + authResult);
        final String requestRefreshToken = JwtTokenUtil.getRequestRefreshToken(request);

        // TODO 마냥 연장 해주지말고, 기간이 조금 남았을 때 연장해주기
        if (!StringUtils.isEmpty(requestRefreshToken)) {

            // refresh Token 기간 연장 !!
            final String updateRefreshToken = jwtTokenService.updateRefreshToken(requestRefreshToken);

            //  response 에 updateRefreshToken 넣기
            response.addHeader("refreshToken", updateRefreshToken);
        }
    }
}