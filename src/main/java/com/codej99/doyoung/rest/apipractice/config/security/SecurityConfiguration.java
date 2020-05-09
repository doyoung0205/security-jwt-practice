package com.codej99.doyoung.rest.apipractice.config.security;

import com.codej99.doyoung.rest.apipractice.config.security.handler.CustomAccessDeniedHandler;
import com.codej99.doyoung.rest.apipractice.config.security.handler.CustomAuthenticationEntryPoint;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.JwtAuthenticationFilter;
import com.codej99.doyoung.rest.apipractice.config.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;

@RequiredArgsConstructor
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private final JwtTokenProvider jwtTokenProvider;


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(Collections.singletonList("*"));// localhost:8080
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable() // rest api 이므로 기본설정 사용안함. 기본설정은 비인증시 로그인폼 화면으로 리다이렉트 된다.
                .csrf().disable() // rest api이므로 csrf 보안이 필요없으므로 disable처리.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // jwt token으로 인증할것이므로 세션필요없으므로 생성안함.
            .and()
                .exceptionHandling().accessDeniedHandler(new CustomAccessDeniedHandler())
            .and()
                .exceptionHandling().authenticationEntryPoint(new CustomAuthenticationEntryPoint())
            .and()
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class); // jwt token 필터를 id/password 인증 필터 전에 넣어라.
    }

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .cors()
//            .and()
//                .httpBasic().disable() // rest api 이므로 기본설정 사용안함. 기본설정은 비인증시 로그인폼 화면으로 리다이렉트 된다.
////                .csrf().disable() // rest api 이므로 csrf 보안이 필요없으므로 disable처리.
//                .csrf()
//                .ignoringAntMatchers("/login")
//                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//            .and()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // jwt token으로 인증할것이므로 세션필요없으므로 생성안함.
//            .and()
//                .authorizeRequests() // 다음 리퀘스트에 대한 사용권한 체크
//                .antMatchers("/*/signin", "/*/signup").permitAll() // 가입 및 인증 주소는 누구나 접근가능
//                .antMatchers(HttpMethod.GET, "/exception/**", "helloworld/**").permitAll() // hellowworld로 시작하는 GET요청 리소스는 누구나 접근가능
//                .anyRequest().hasRole("USER") // 그외 나머지 요청은 모두 인증된 회원Z만Z 접근 가능
//            .and()
//                .exceptionHandling().authenticationEntryPoint(new CustomAuthenticationEntryPoint())
//            .and()
//                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class); // jwt token 필터를 id/password 인증 필터 전에 넣어라.
//    }

//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring().antMatchers("/v2/api-docs",
//                "/configuration/ui",
//                "/swagger-resources/**",
//                "/configuration/security",
//                "/swagger-ui.html",
//                "/webjars/**");
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}