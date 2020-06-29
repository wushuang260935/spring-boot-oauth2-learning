package org.liam.cloud.learning.oauth2.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	BCryptPasswordEncoder encoder;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory() 
		.withClient("client") //clientId就是oauth2协议中的client identifier
	    .secret(encoder.encode("abcdefg")) //因为我们系统中，注入了BCryptPasswordEncoder，所以进行client basic or post authentication
	    //的时候会对客户端发送过来的原生client secret进行加密。为了对比成功，因此这里需要加密。
	    .scopes("resource.read")
	    .authorizedGrantTypes("authorization_code")
	    //.authorities("/oauth/token")
	    .redirectUris("http://localhost:81/endpoint/token") //client的重定向端点，这个端点的主要作用是
		//1.接收auth server重定向过来的地址(里面包含authorization code)
		//2.然后发送请求给auth server获取access_token
	    .and()//还可以继续配置下一个客户端
	    .withClient("resDemo")
	    .secret(encoder.encode("abcdefg"))
	    .authorities("/oauth/check_token");
	}	
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer server) {
		server.allowFormAuthenticationForClients()//如果auth server开启client post authentication，那么client的id和secret需要在form表单中传过来
		.checkTokenAccess("isAuthenticated()");//这个属性主要用于资源服务器获取到access_token后，访问auth server的/oauth/check_token端点验证access_token合法性。
	}
}
