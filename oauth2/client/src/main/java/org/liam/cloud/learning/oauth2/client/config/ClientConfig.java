package org.liam.cloud.learning.oauth2.client.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class ClientConfig extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(HttpSecurity security) throws Exception {
		security
        .authorizeRequests()
        .anyRequest().authenticated()
        .and()
        .oauth2Login()
        .redirectionEndpoint()
        .baseUri("/endpoint/token");
	}
}
