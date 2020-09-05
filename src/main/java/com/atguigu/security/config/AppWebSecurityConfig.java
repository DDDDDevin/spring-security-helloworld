package com.atguigu.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;

@Configuration //声明一个配置类。配置类就相当与XML配置文件的作用。
@EnableWebSecurity //启用权限框架功能
public class AppWebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    DataSource dataSource;

    /*对请求进行认证处理*/
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
       //默人 认证处理，任何登录信息都无法认证
//        super.configure(auth);

        //实验四：自定义认证用户信息（基于内存的认证方式）
        auth.inMemoryAuthentication()
                .withUser("zhangsan").password("123456").roles("学徒","大师")
                .and()
                .withUser("lisi").password("123123").authorities("罗汉拳","武当长拳");
    }


    //对请求进行授权处理
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //默认授权，对所有的资源进行拦截，使得所有资源都‘不允许’访问
//        super.configure(http);

        /*实验一：授权首页和静态资源*/
        //授权请求
        //ant 路径规则
        // *匹配任意字符
        // **匹配任意路径下的任意资源
        // ？匹配一个字符
//        http.authorizeRequests()
//                .antMatchers("/layui/**","/index.jsp").permitAll() //
//                .anyRequest().authenticated(); //剩下的只要登录认证了就可以访问

        //6.实验六：基于角色的访问控制
        http.authorizeRequests()
                .antMatchers("/layui/**","/index.jsp").permitAll() //允许所有人访问的资源【无需登录】
                .antMatchers("/level1/**").hasRole("学徒")
                .antMatchers("/level2/**").hasRole("大师")
                .antMatchers("/level3/**").hasRole("宗师")
                .anyRequest().authenticated(); //剩下的只要登录认证了就可以访问
        //	将.anyRequest().authenticated()错误的设置在前面，后面的设置就不起作用了。



        /*3.2	实验二：授权默认登录页（当发生403无权访问时转到默认登录页
                这些资源不用登陆就可访问）、及自定义登录页*/
//        http.formLogin();//授权默认登录页
//        http.formLogin().loginPage("/index.jsp"); //自定义登录页

        //实验三：自定义表单登录逻辑分析
        http.formLogin().loginPage("/index.jsp")
                .loginProcessingUrl("/doLogin") //表单提交地址
                .usernameParameter("loginacct") //自定义参数名
                .passwordParameter("userpwd")
                .defaultSuccessUrl("/main.html");

        //实验五：用户注销完成
        http.logout().logoutUrl("/logout")
                .logoutSuccessUrl("/index.jsp");

        // 实验七：自定义访问拒绝处理页面
//        http.exceptionHandling().accessDeniedPage("/unauth.html");

        //自定义异常处理器
        http.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
            @Override
            public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                 httpServletRequest.setAttribute("message", e.getMessage());
                 httpServletRequest.getRequestDispatcher("/WEB-INF/views/unauth.jsp").forward(httpServletRequest, httpServletResponse);
            }
        });

        //实验八：记住我功能-Cookie版
//        http.rememberMe();

        //实验九：记住我功能-数据库版
        JdbcTokenRepositoryImpl ptr = new JdbcTokenRepositoryImpl();
        ptr.setDataSource(dataSource);
        http.rememberMe().tokenRepository(ptr);

        //暂时禁用csrf （防止跨站请求伪造）
        http.csrf().disable();
    }
}
