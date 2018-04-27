package authserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableResourceServer
@SpringBootApplication
public class Auth2ServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(Auth2ServerApplication.class, args);
	}
	

	@Configuration
	@EnableWebSecurity
	protected static class webSecurityConfig extends WebSecurityConfigurerAdapter {

		@Bean
		@Override
		protected UserDetailsService userDetailsService() {
			InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
			// password=123456
			manager.createUser(User.withUsername("user1")
					.password("{bcrypt}$2a$10$OHCjHUncoIJL2iJdjKqvb.crAxKSENYFQIdsk7LVWOPOqTf4wYsc6")
					.authorities("USER").build());
			manager.createUser(User.withUsername("user2")
					.password("{bcrypt}$2a$10$OHCjHUncoIJL2iJdjKqvb.crAxKSENYFQIdsk7LVWOPOqTf4wYsc6")
					.authorities("USER").build());
			return manager;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.csrf().disable();
			http.requestMatchers().antMatchers("/oauth/**", "/login/**", "/logout/**").and().authorizeRequests()
					.antMatchers("/oauth/**").authenticated().and().formLogin().permitAll();
			
//			 http
//             .authorizeRequests()
//             .anyRequest().authenticated()
//             .and()
//             .formLogin().and()
//             .csrf().disable()
//             .httpBasic();
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(userDetailsService());
		}

		@Override
		public void configure(WebSecurity web) throws Exception {
			web.ignoring().antMatchers("/favor.ioc");
		}

		@Override
		@Bean
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class OAuth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.inMemory().withClient("client")
					// password=123456
					.secret("{bcrypt}$2a$10$OHCjHUncoIJL2iJdjKqvb.crAxKSENYFQIdsk7LVWOPOqTf4wYsc6")
					.authorizedGrantTypes("authorization_code", "client_credentials", "refresh_token", "password",
							"implicit")
					.scopes("server");
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints
					// .tokenStore(tokenStore)
					.authenticationManager(authenticationManager)
			// .userDetailsService(userDetailsService)
			;
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
			//oauthServer.allowFormAuthenticationForClients();//将禁用以下授权类型： "client_credentials","password"
		}
	}

	@Configuration
	@EnableResourceServer
	static class ResourceSC extends ResourceServerConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/user").authorizeRequests().anyRequest().authenticated();
		}
	}
}
