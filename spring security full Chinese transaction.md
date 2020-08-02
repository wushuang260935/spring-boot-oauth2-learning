# Spring security full Chinese Transaction
spring security中文文档

# servlet应用

spring security通过拦截器（filter）和servlet容器整合在一起。这就意味着：不管你是否使用了spring。只要使用了servlet容器就能使用spring security。

# Hello spring security
[例子]([https://github.com/spring-projects/spring-security/tree/master/samples/boot/helloworld])
[最小源码](https://start.spring.io/starter.zip?type=maven-project&language=java&packaging=jar&jvmVersion=1.8&groupId=example&artifactId=hello-security&name=hello-security&description=Hello%20Security&packageName=example.hello-security&dependencies=web,security)

# spring boot 自动配置

spring boot 会默认提供以下配置:

> 开启spring security的默认配置: 创建一个叫做"springSecurityFilterChain"的拦截器。这个拦截器负责所有的安全操作。（包括:URL安全相关操作，用户名密码认证，登录表单重定向。等）

> 创建一个用户名为“user”，密码随机并在控制台打印的用户(org.springframework.security.core.userdetails.User)。然后把给User装到UserDetailsService Bean中。

> 注册一个负责处理所有请求的“springSecurityFilterChain” Bean。这个 Bean其实是org.springframework.security.web.FilterChainProxy

spring boot其实没有配置多少spring security。但是下面的这些其实已经够多了:

> 要想访问应用，至少需要一个已认证的用户

> 生成了一个默认的登录页面

> 默认允许用户名为“user”，密码为控制台打印的那传随机码。登录应用。

> 那串随机码使用了加密机制BCrypt

> 允许登出

> 阻止CSRF攻击

> [Session Fixation](https://en.wikipedia.org/wiki/Session_fixation)保护

.加了一些请求头:

> [HTTP Strict Transport Security](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)

> [X-Content-Type-Options](https://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx)整合

> 缓存控制（如果后端的response配置了缓存头的话，这个配置不会生效）

> [X-XSS-PROTECTION](https://msdn.microsoft.com/en-us/library/dd565647(v=vs.85).aspx)

> X-Frame-Options 保护。主要是为了阻止[ClickJacking](https://en.wikipedia.org/wiki/Clickjacking)

.和下面的Servlet API方法:

> [HttpServletRequest#getRemoteUser()]

> [HttpServletRequest.html#getUserPrincipal()]

> [HttpServletRequest.html#isUserInRole(java.lang.String)]

> [HttpServletRequest.html#login(java.lang.String, java.lang.String)]

> [HttpServletRequest.html#logout()]

# Servlet Security 全景图

这部分我们讨论Spring Security的基础设施。主要包括这几块：认证(Authentication).授权(Authorization).等。

## 拦截器视角

Spring Security对Servlet的支持非常依赖于拦截器。所以我们第一视觉便是查看拦截器在springsecurity中的角色。下面的图片很经典。

[图片](https://docs.spring.io/spring-security/site/docs/5.3.3.BUILD-SNAPSHOT/reference/html5/images/servlet/architecture/filterchain.png)

 客户端向应用发送一个请求。容器就会创建一个拦截链(FilterChain)。并且包含一个可以处理此请求的servlet（这里的意思是本质上是servlet，后同）。
 
 > 拦截器的作用就是。一旦拦截器执行了某种判断之后。可以决定放行或者禁止请求流向下游拦截器或者说servlet。
 > 有的拦截器还会修改HttpServletRequest或者HttpServletResponse的属性。
 下面是一个拦截器的例子:
 
 ```
 public void doFilter(ServletRequest request,ServletResponse response){
 	\\执行到下游链之前的某些操作。
 	
 	chain.doFilter(request,response);
 	
 	\\下游链路执行完成之后的操作。
 	
 }
 ```
 
 由于拦截器只能影响下游的拦截器或者servlet。因此拦截器之间的顺序就变得很重要了。
 
 ## 委托拦截代理(DelegatingFilterProxy)
 
 spring提供了一个叫做"DelegatingFilterProxy"的拦截器实例:org.springframework.web.filter.DelegatingFilterProxy.我们先看一张DelegatingFIlterProxy的图片和它的部分代码。
 
 
 [图片](https://docs.spring.io/spring-security/site/docs/5.3.3.BUILD-SNAPSHOT/reference/html5/images/servlet/architecture/delegatingfilterproxy.png)
 
```
public void doFilter(ServletRequest request,ServletRepsonse response){
	//懒加载一个注册为Bean的拦截器
	
	//依照上面的图片的话，DelegatingFilterProxy的delegate属性就是Filter0实例。
	Filter delegate = getFilterBean("filter0");
	//然后把工作委托给它干。
	delegate.doFilter(request,response);

}
```

 上面的图片和代码展示了DelegatingFilterProxy是怎么把我们的普通Bean嵌入进拦截链和servlet之间的。
 
 我们知道。定义一个拦截器不仅需要实现Filter接口，还需要再web.xml中声明才能正常使用。因此“声明”这一步有点违背spring的 原则。所以spring
 想到了一个办法：
 创建一个“正常”的拦截器DelegatingFilterProxy。因此它由servlet容器创建，它的生命周期由servlet容器来控制。但是同时这个拦截器又从spring上下文中寻找Bean Filter0。Filter0虽然实现了Filter接口。但是它没有声明到web.xml中。因此它的生命周期由spring上下文管理。然后DelegatingFilterProxy就把它的工作委托给Filter0处理。
这样就实现了普通Bean嵌入到拦截器链和Servlet容器内。只要你想，Filter0还可以创建自己的链路。Filter1,Filter2....FilterN.我们完全可以执行完了之后。再敲一行代码，继续执行servlet容器后续的链路。

总结：DelegatingFIlterProxy这个代理的主要功能是把spring上下文和servlet容器的生命周期桥接起来。在执行的过程中，servlet容器对嵌入进来的spring bean是无感的（就是管不了它的意思）。

DelegatingFilterProxy还有另一个好处，DelegatingFIlterProxy实质上造成了spring Bean Filter延迟加载的效果。这一点其实很重要。因为我们根据servlet容器的特性，容器在启动之前需要注册好所有的Filter。而这个时候spring Bean还没有加载。（关于spring容器通常采用ContextLoadListener来加载spring bean的知识自行了解)。

## FilterChainProxy

有了上面的认识。当然我们就是用它来创建Security拦截链路了。我们给Security拦截链路创建了一个接口SecurityFilterChain。实现了此接口的bean就是一个security拦截器链路。
请注意一个security拦截器链路与Security bean之间的关系。一个链路bean里面有多个拦截器bean。而spring security又可以创建很多个链路。
	另外，我们还有一点需要知道，DelegatingFilterProxy是jdk1.5的一个servlet Filter它无法指挥spring bean。因此我们还需要一个调度security链路的Filter。这个Filter就是FilterChainProxy。有了它，就变成了DelegatingFilterProxy把所有的工作委托给FilterChainProxy。然后FilterChainProxy从spring容器中找到所有实现了SecurityFilterChain接口的链路。然后选择一个合适的链路来处理request，response请求。就是下面这张图:
	[图片](https://docs.spring.io/spring-security/site/docs/5.3.3.BUILD-SNAPSHOT/reference/html5/images/servlet/architecture/securityfilterchain.png)
	
由此可知FilterChainProxy是所有Spring Security对servlet支持的起点。如果你要仔细尝试调试spring security的话，你可以从FilterChainProxy开始。

还有，由于FilterChainProxy的特殊地位。它还需要执行Spring Security的其他重要任务。比如说：它负责清理SecurityContext以访内存泄漏。它还负责开启spring security防火墙(HttpFirewall)。这是一种防止各种http攻击的重要手段。它还赋予了spring security更多灵活性，比如它可以控制我们的链路什么时候执行。实际上FilterChainProxy对于链路的调度策略依赖于链路对象中的一个属性:RequestMatcher。让我们通过下面这张图片来了解一番

[图片](https://docs.spring.io/spring-security/site/docs/5.3.3.BUILD-SNAPSHOT/reference/html5/images/servlet/architecture/multi-securityfilterchain.png)

有这么一个规则，所有链路中第一个匹配的链路会被执行，剩下的就被忽略了。那么如上图所示，假设一个/api/message的请求被分发进来了。那么只有链路SecurityFilterChain0会被执行，因为它是第一个匹配成功的。即使SecurityFilterChainN也满足这个请求。

这里我们就知道，RequestMatcher就是一个包含逻辑判断的对象。比如SecurityFilterChain0的RequestMatcher包含的逻辑就是"/api/**"。SecurityFilterChainN的RequestMatcher包含的逻辑就是"/**".我们后面还会专门学到RequestMatcher.

另外请注意到SecurityFilterChain0有3个filter bean。SecurityFilterChainN有4个filter bean。链路中的filter bean个数是不固定。甚至有时候为了忽略某种http request.链路设置会创建0个bean。

## Security Filter bean

Security Filter Bean是通过SecurityFilgterChain API进入到SecurityFilterChain对象中的。并且，每一个Filer bean之间的顺序非常的重要。虽然大多数时候我们不用去硬记他们的顺序。但下面的filter bean我们列出来，以防万一以后我们需要查询他们之间的顺序：

ChannelProcessingFilter

ConcurrentSessionFilter

WebAsyncManagerIntegrationFilter

SecurityContextPersistenceFilter

HeaderWriterFilter

CorsFilter

CsrfFilter

LogoutFilter

OAuth2AuthorizationRequestRedirectFilter

Saml2WebSsoAuthenticationRequestFilter

X509AuthenticationFilter

AbstractPreAuthenticatedProcessingFilter

CasAuthenticationFilter

OAuth2LoginAuthenticationFilter

Saml2WebSsoAuthenticationFilter

UsernamePasswordAuthenticationFilter

ConcurrentSessionFilter

OpenIDAuthenticationFilter

DefaultLoginPageGeneratingFilter

DefaultLogoutPageGeneratingFilter

DigestAuthenticationFilter

BearerTokenAuthenticationFilter

BasicAuthenticationFilter

RequestCacheAwareFilter

SecurityContextHolderAwareRequestFilter

JaasApiIntegrationFilter

RememberMeAuthenticationFilter

AnonymousAuthenticationFilter

OAuth2AuthorizationCodeGrantFilter

SessionManagementFilter

ExceptionTranslationFilter

FilterSecurityInterceptor

SwitchUserFilter

## 处理Security异常

上面的ExceptionTranslationFilter负责把AccessDeniedException和AuthenticationException翻译成相关http response属性。它的操作流程如[下图](https://docs.spring.io/spring-security/site/docs/5.3.3.BUILD-SNAPSHOT/reference/html5/images/servlet/architecture/exceptiontranslationfilter.png)

1.首先，ExceptionTranslationFIlter执行FilterChain.doFilter(request,response)来处理一个http请求。
2.如果ExceptionTranslationFilter发现这个请求中的用户没有认证。那么就进入认证流程。

> 清空SecurityContextHolder。
>把请求对象HttpServletRequest缓存起来，放到RequestCache中。目的就是为了当用户认证成功之后，把它拿出来继续做请求处理。
>AuthenticationEntryPoint是用来向客户(client就是用户)请求凭证(Credenticals)的。例如，它会重定向到登录页面或者在响应头中加”WWW-Authentication"。

3.如果在处理请求过程中获取到AccessDeniedException。那么就会进入AccessDeniedhandler处理失败的请求。

如果执行过程中既没有抛出AccessDeniedException也没有抛出AuthenticationException。那么ExcetpionTranslationFilter就不会干任何事情。

下面让我们简单看一看它的代码:

```
try{
	filterChain.doFilter(request,response);//1
}catch(AccessDeniedException | AuthenticationException e){
	if(!authenticated || e instanceof AuthenticationException){
		startAuthentication();//2
	}else{
		accessDenied();//3
	}
}
```

# 认证(Authentication)

spring security对认证(Authentication)的支持非常全面。这部分我们会详细讨论他们的基础组件。

> SecurityContextHolder 它是储存已认证用户详细信息的地方
> SecurityContext 从SecufrityContextHolder中获得的一种上下文，里面主要是已认证用户的认证信息(Authentication)
> Authentication 认证信息，它最重要的用途就是，用于AuthenticationManager中，在AuthenticationManager
进行认证的时候向它提供用户的凭证(Credentials).或者从SecurityContext中直接提供当前用户。
> grantedAuthority 一个Authority(可以叫做"授权"或者叫做"权力")会在认证(Authentication)之后赋给当事人(Principal)
> AuthenticationManager 是一个接口，它里面的方法是对spring security进行认证的规范。
> ProviderManager 最常用的AuthenticationManager实现类。
> AuthenticationProvider 既然AuthenticationManager是对整个认证过程的规范，所以AuthenticationManager肯定包含了很多大的步骤，
那么AuthenticationProvider就是对认证用户这一步关键步骤的规范。也可以理解为延申，因为认证方式多种多样，这里我们只定义规范，具体实现就交给实现类去办。
> Request Credenticals with AuthenticationEntryPoint 用于向客户（client 就是用户）请求凭证 。凭证(Credenticals)：一般情况下表示用户提交的密码。
> AbstractAuthenticationProcessingFilter 一个基类拦截器。上面这些基础组件都放在这个拦截器里面。这个基类负责把这些组件串起来。

下面是一些常见的认证方式

> Username and password 使用用户名密码认证
> oAuth2 2.0 Login 使用openId Connect进行OAuth2登录,比如很多网站使用的”用谷歌账号登录"。或者使用非标准Oauth2登录,比如"使用github账号登录“。
> SAML 2.0 Login
> Central Authentication Server(CAS)
> Remember me 登录成功之后”记住我“，下次就不用登录啦，这也是一种认证方式
> JAAS Authentication 
> OpenID 
> Pre-Authentication Scenarios 
> X509 Authentication 

## SecurityContextHolder

spring security 认证模型的核心就是SecurityContextHolder。它的内部包含了SecurityContext。结构如下图:
[图片](https://docs.spring.io/spring-security/site/docs/5.3.3.BUILD-SNAPSHOT/reference/html5/images/servlet/authentication/architecture/securitycontextholder.png)

SecurityContextHolder是存储已认证用户的详细信息的地方。Spring Security并不关心用户信息是怎么注入到SecurityContextHolder中的。如果SecurityContextHolder里面包含了一个上下文，那么这个上下文中的用户就是当前登录用户。

下面是使用SecurityContextHolder的例子

```
SecurityContext context = SecurityContextHolder.createEmptyContext();//1
Authentication authentication = new TestingAuthenticationToken("username","password","ROLE_USER");//2
context.setAuthentication(authentication);

SecurityContextHolder.setContext(context);//3
```

上面的例子需要注意以下几点:

> 如果你使用SecurityContextHolder.getContext().setAuthentication(authentication)设置认证用户，就有可能会出现线程问题。所以，我们应该像例子中，创建一个空上下文。然后依次存到SecurityContextHolder中。

> 如果你想在某个地方获取用户凭证(Credenticals)。可以使用SecurityContextHolder

```
SecurityContext context = SecurityContextHolder.getContext();
Authentication authentication = context.getAuthentication();
String userName = authentication.getName();
Object principal  = authentication.getPrincipal();

Collection<? extend GrantedAuthority> authorities = authentication.getAuthorities();
```

默认地，SecurityContextHolder使用ThreadLocal存储他们的信息。这就意味着SecurityContext在这个线程执行的所有地方都可以获取到。这就是我们开发中总是能够渠道SecurityContext的原因。

同时我们还要考虑到，有些应用会创建自己的线程来做某些业务。这中自定义线程的情况难以避免。而这种自定义的线程就不能取到原来的ThreadLocal了。因此spring
security在SecurityContextHolder中设置了几种策略，并对他们做了支持。
> SecurityContextHolder.MODE_GLOBAL。这个策略规定虚拟机中的所有线程都可以共享SecurityContext。
> SecurityContextHolder.MODE_INHERITABLETHREADLOCAL.从主线程中创建的线程可以共享SecurityContext。
> SecurityContextHolder.MODE_THREADLOCAL.是默认策略。需要说一下的是要修改成上述两个策略有两种方式。第一种是配置系统属性。第二种是调用SecurityContextHolder的静态方法。 另外，修改SecurityContextHolder策略需要谨慎考虑。

## Authentication

之前介绍了Authentication接口是一种对认证方式的规范。我们再深入介绍下:

> Authentication实现类会作为AuthenticationManager的Authenticate方法入参传入AuthenticationManager中。然后提供用户凭证(Credentials)用来认证。
>  如果从SecurityContext中获取到了Authentication对象。那么就代表了已登陆用户。

> principal(当事人或者叫做主体)是Authentication的属性。如果认证方式为username/password.那么principal就是一个UserDetails对象。
> Credentials 是Authentication的属性。一般情况下就是一个password。认证通过后会被清空以免泄露。
> authorities 是authentication的属性。用来储存授予用户的权限。

## GrantedAuthority

 GrantedAuthority就是应用授予登录用户的各种权限。我们可以这样获取：Authentication.getAuthorities()。得到的结果是一个集合。一般情况下，集合中就是授予登录用户的角色。而我们大多数的应用中，角色和访问地址之间是一对多的关系。因此拥有角色就意味着用于该角色对应的访问地址全线。
 
 我们常的username/password登录方式。grantedauthority一般由userdetailservice加载。
 
## AuthenticationManager
 
AuthenticationManager接口中的authenticate方法，入参是一个带认证的Authentication对象。等到它认证通过之后，也会把Authentication作为出参返回。之后Authentication对象就会进入SecurityContext中。

## providerManager

 这部分我们来看看最常用的AuthenticationManager实现-ProviderManager。ProviderManager本身维护了一个认证列表，就是实现了AuthenticationProvider接口的对象集合。在认证环节，ProviderManager会遍历这个列表，因此每一个实现了AuthenticationProvider都会尝试验证当前用户。一般会返回三种状态，验证成功，验证失败，或者交给下游AuthenticationProvider验证。
 
> 如果你发现你的应用中有多个ProviderManager这并不奇怪。因为这是spring security对Providermanager进行分类的结果。每一个ProviderManager的侧重点不一样。里面的AuthenticationProvider集合也不一样。

> 通常，ProviderManager之间是有层级关系的。一般他们会有一个共同的上级ProviderManager.这里就不详细分析了。

## AuthenticationProvider

我们在上面已经介绍过了，就不重复了。

## 使用AuthenticationEntryPoint发送凭证请求 
 
当客户端发送的http请求无法认证到某一个用户时。spring security会在ExceptionTranslationFilter中使用AuthenticationEntryPoint操作HttpRequest,HttpResponse。一般的AuthenticationEntryPoint实现类会重定向到某一个登录页面。或者是在响应中添加WWW-Authenticate请求头。
 
## AbstractAuthenticationProcessingFilter

之前，我们讲过，AbstractAuthenticationprocessingFilter是把spring security的基础组件都囊括、组织起来。使用这些组件完成一整个流程，也就是说它是实现spring security的目标：认证，授权的一个最低配(借助汽车的概念，最低配)。下面我们就来看看它是怎么工作的，先看张图:

[AbstractAuthenticationProcessingFilter工作图](https://docs.spring.io/spring-security/site/docs/5.3.3.BUILD-SNAPSHOT/reference/html5/images/servlet/authentication/architecture/abstractauthenticationprocessingfilter.png)


> 当用户提交了凭证后，AbstractAuthenticationProcessingFilter会在HttpServletRequest中创建一个Authentication对象。但是