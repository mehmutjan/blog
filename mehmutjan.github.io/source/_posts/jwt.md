---
title: jwt 使用方法
date: 2019-01-05 20:34:21
categories: 
- php
-symfony
tags: 
- php
- symfony
---

###介绍
* JSON Web Token（JWT）是JSON的基于开放标准（RFC 7519），用于创建访问令牌该断言权利要求中的一些数字。例如，服务器可能会生成一个令牌，其中声明“以管理员身份登录”并将其提供给客户端。然后客户端可以使用该令牌来证明它以管理员身份登录。令牌由一方的私钥（通常是服务器）签名，以便双方（另一方已经通过一些合适和可靠的方式拥有相应的公钥）能够验证令牌是否合法。该令牌被设计成紧凑的，URL -safe和可用特别是在Web浏览器中 的单点登录（SSO）上下文。JWT声明通常可用于传递身份提供者与服务提供者之间的身份验证用户身份，或业务流程所要求的任何其他类型的声明。
* JWT依赖于其他基于JSON的标准：JWS（JSON Web签名）RFC 7515和JWE（JSON Web加密）RFC 7516。

### 安装
#### 加载
 
	composer require lexik/jwt-authentication-bundle

####生成SSH密钥

	$ mkdir -p config/jwt ＃对于Symfony3 +，不需要-p选项
	$ openssl genrsa -out config/jwt/private.pem -aes256 4096
	$ openssl rsa -pubout -in config/jwt/private.pem -out config/jwt/public.pem
	
	
#### 如果第一个openssl命令强制您输入密码，请使用以下命令来解密私钥

	$ openssl rsa -in config/jwt/private.pem -out config/jwt/private2.pem
	$ mv config/jwt/private.pem config/jwt/private.pem-back
	$ mv config/jwt/private2.pem config/jwt/private.pem

### 配置
####在你的下面配置SSH密钥路径 config.yml:

	lexik_jwt_authentication：
     private_key_path：'％jwt_private_key_path％'
     public_key_path：   '％jwt_public_key_path％'
     pass_phrase：       '％jwt_key_pass_phrase％'
     token_ttl：         '％jwt_token_ttl％'
     
####配置你的 parameters.yml:

	jwt_private_key_path: '%kernel.root_dir%/../var/jwt/private.pem' #ssh private key path
	jwt_public_key_path:  '%kernel.root_dir%/../var/jwt/public.pem'  #ssh public key path
	jwt_key_pass_phrase:  ''   # ssh key pass phrase                                      
	jwt_token_ttl:        3600


####配置你的 security.yml:

	security:
    # ...

    firewalls:

        login:
            pattern:  ^/api/login
            stateless: true
            anonymous: true
            form_login:
                check_path:               /api/login_check
                success_handler:          lexik_jwt_authentication.handler.authentication_success
                failure_handler:          lexik_jwt_authentication.handler.authentication_failure
                require_previous_session: false

        api:
            pattern:   ^/api
            stateless: true
            guard:
                authenticators:
                    - lexik_jwt_authentication.jwt_token_authenticator

    access_control:
        - { path: ^/api/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/api,       roles: IS_AUTHENTICATED_FULLY }
####配置你的 routing.yml:

	api_login_check:
		path: /api/login_check
	
###用法
####获取令牌

第一步是使用其凭证对用户进行身份验证。匿名访问的防火墙上的经典form_login将完美无缺。

只需将提供的 ```lexik_jwt_authentication.handler.authentication_success``` 服务设置为成功处理程序即可生成令牌并将其作为json响应主体的一部分发送。

存储它（客户端），JWT可以重用，直到它的ttl过期（默认3600秒）。

注意：您可以使用一个简单的curl命令来测试获取令牌，如下所示:

	curl -X POST http：//localhost：8000 / api / login_check -d _username = johndoe -d _password = test
	
如果它有效，你会收到这样的东西：

	{
	   "token" : "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJleHAiOjE0MzQ3Mjc1MzYsInVzZXJuYW1lIjoia29ybGVvbiIsImlhdCI6IjE0MzQ2NDExMzYifQ.nh0L_wuJy6ZKIQWh6OrW5hdLkviTs1_bau2GqYdDCB0Yqy_RplkFghsuqMpsFls8zKEErdX5TYCOR7muX0aQvQxGQ4mpBkvMDhJ4-pE4ct2obeMTr_s4X8nC00rBYPofrOONUOR4utbzvbd4d2xT_tj4TdR_0tsr91Y7VskCRFnoXAnNT-qQb7ci7HIBTbutb9zVStOFejrb4aLbr7Fl4byeIEYgp2Gd7gY"
	}

####使用令牌

只需将每个请求的JWT传递给受保护的防火墙，无论是作为授权头还是作为查询参数。

默认情况下只启用授权标题模式：```Authorization: Bearer {token}```

请参阅[配置参考](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/1-configuration-reference.md)文档以启用查询字符串参数模式或更改标题值前缀。

##### 例子
请参阅[功能测试受JWT保护的api](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/3-functional-testing.md)文档或[沙箱应用程序](https://github.com/slashfan/LexikJWTAuthenticationBundleSandbox)以获得完整的工作示例。

##### 笔记
#####关于令牌过期
令牌到期后的每个请求都将导致401响应。重新进行身份验证过程以获取新令牌。

也许你想使用刷新令牌来更新你的JWT。在这种情况下，您可以检查[JWTRefreshTokenBundle](https://github.com/gesdinet/JWTRefreshTokenBundle)。

#####处理CORS请求
这更多的是与Symfony2相关的主题，但请参阅使用CORS请求文档获取处理[CORS请求](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/4-cors-requests.md)的快速说明。

#####无状态的form_login替换
使用form_login安全工厂非常简单，但它涉及cookie交换，即使无状态参数设置为true。

这可能不是问题，这取决于调用API的系统（如典型的SPA）。但如果是这样，请看看[GfreeauGetJWTBundle](https://github.com/gfreeau/GfreeauGetJWTBundle)，它提供了form_login的无状态替换。

#####模拟
有关使用JWT模拟用户的信息，请参阅[https://symfony.com/doc/current/security/impersonating_user.html](https://symfony.com/doc/current/security/impersonating_user.html)

对于Apache用户的重要提示
正如指出[此链接](http://stackoverflow.com/questions/11990388/request-headers-bag-is-missing-authorization-header-in-symfony-2)和[这一个](http://stackoverflow.com/questions/19443718/symfony-2-3-getrequest-headers-not-showing-authorization-bearer-token/19445020)，Apache服务器将去掉任何Authorization header没有有效的HTTP基本认证格式。

如果您打算使用此捆绑包的授权标头模式（并且您应该），请将这些规则添加到您的```VirtualHost```配置中：

	RewriteEngine On
	RewriteCond %{HTTP:Authorization} ^(.*)
	RewriteRule .* - [e=HTTP_AUTHORIZATION:%1]

###更多文档
####以下文件可供使用：
* [配置参考](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/1-configuration-reference.md)
* [数据定制和验证](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/2-data-customization.md)
* [在功能上测试JWT保护的api](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/3-functional-testing.md)
* [处理CORS请求](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/4-cors-requests.md)
* [JWT编码器服务定制](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/5-encoder-service.md)
* [扩展JWTTokenAuthenticator](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/6-extending-jwt-authenticator.md)
* [以编程方式创建JWT令牌](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/7-manual-token-creation.md)
* [无数据库用户提供程序](https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/Resources/doc/8-jwt-user-provider.md)