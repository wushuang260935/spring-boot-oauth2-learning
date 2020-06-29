package org.liam.cloud.learning.oauth2.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

/**
 * Hello world!
 *
 */
@EnableAuthorizationServer
@SpringBootApplication
public class ServerApplication 
{
    public static void main( String[] args )
    {
    	SpringApplication.run(ServerApplication.class, args);
    }
}
