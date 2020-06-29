package org.liam.cloud.learning.oauth2.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter{

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder;
	}
	
	@Bean
	public UserDetailsService userDetailsService(@Autowired BCryptPasswordEncoder encoder) {
		UserDetailsService service = new CustomizedUserDetailsService(encoder);
		return service;
	}
	
	private class CustomizedUserDetailsService implements UserDetailsService{

		BCryptPasswordEncoder encoder = null;
		
		public CustomizedUserDetailsService(BCryptPasswordEncoder encoder) {
			this.encoder = encoder;
		}
		
		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			//dataSource.getConnection().prepareStatement("select * from sysuser");
			UserDetails user = User
					.builder()
					.username(username)
					.password(encoder.encode("123456"))
					.authorities("/getmyinfo")
					.build();
			return user;
		}
		
	}
}
