package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    //ctrl + o로 override
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //필터 추가
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);

        //csrf 안쓰겠다
        http.csrf().disable();
        //session 안쓰겠다 (stateless)
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 쓰디 않겠다
        .and()
        .addFilter(corsFilter)  // 인증(로그인)이 필요없을때는 @CrossOrigin 사용, 인증(로그인)이 필요있을때는 시큐리티 필터에 등록 인증
        .formLogin().disable()  // form 태그로 로그인 하는건 안한다
        .httpBasic().disable()  //
        .authorizeRequests()
        .antMatchers("/api/v1/user/**")
        .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/v1/manager/**")
        .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/v1/admin/**")
        .access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll();
    }
}
