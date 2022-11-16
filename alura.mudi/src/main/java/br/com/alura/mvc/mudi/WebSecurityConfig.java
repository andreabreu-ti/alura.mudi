package br.com.alura.mvc.mudi;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private DataSource dataSource;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().anyRequest().authenticated().and()
				.formLogin(form -> form
						.loginPage("/login")
						.defaultSuccessUrl("/home", true)
						.permitAll());
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

		auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(encoder);
		
		//Iniciar o usuário no banco.
//		UserDetails user = User.builder().username("maria").password(encoder.encode("maria")).roles("ADM").build();
//
//		auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(encoder).withUser(user);
	}

	/*
	 * // Autenticação básica, com o usuário em memoria
	 * 
	 * @Override protected void configure(HttpSecurity http) throws Exception {
	 * http.authorizeRequests().anyRequest().authenticated().and() .formLogin(form
	 * -> form.loginPage("/login").permitAll()); }
	 * 
	 * @Override protected void configure(AuthenticationManagerBuilder auth) throws
	 * Exception {
	 * 
	 * BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
	 * 
	 * auth .jdbcAuthentication() .dataSource(dataSource) .passwordEncoder(encoder);
	 * }
	 * 
	 * //Informações em memoria
	 * 
	 * @Bean
	 * 
	 * @Override public UserDetailsService userDetailsService() { UserDetails user =
	 * User.withDefaultPasswordEncoder().username("joao").password("joao").roles(
	 * "ADM").build(); return new InMemoryUserDetailsManager(user); }
	 * 
	 * 
	 * 
	 */
}
