package com.sky.jwt.config;

import com.sky.jwt.token.JwtAccessDeniedHandler;
import com.sky.jwt.token.JwtAuthenticationEntryPoint;
import com.sky.jwt.token.JwtSecurityConfig;
import com.sky.jwt.token.TokenProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/h2-console/**", "/favicon.ico");
    }

/*    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .anyRequest().authenticated();
        return http.build();
    }*/

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // token을 사용하는 방식이기 때문에 csrf를 disable
                .csrf().disable()

                //.addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)

                //만들었던 클래스를 이용
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // enable h2-console
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 세션을 사용하지 않기 때문에 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeHttpRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
                //.requestMatchers("/api/hello", "/api/authenticate", "/api/signup").permitAll()
                //.requestMatchers(PathRequest.toH2Console()).permitAll()
                .anyRequest().authenticated()

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));

        return httpSecurity.build();
    }
}
