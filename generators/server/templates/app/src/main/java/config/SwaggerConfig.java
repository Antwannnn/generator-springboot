package <%= packageName %>.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@OpenAPIDefinition(
        info = @Info(title = "<%= appName %>", version = "v1"),
        servers = @Server(url = "/")<%_ if (authenticationType !== 'none') { _%>,
        security = @SecurityRequirement(name = "<%_ if (authenticationType === 'oauth2' || authenticationType === 'sso') { _%>oauth2<%_ } else if (authenticationType === 'jwt') { _%>bearerAuth<%_ } else if (authenticationType === 'basic') { _%>basicAuth<%_ } _%>")<%_ } _%>)
<%_ if (authenticationType === 'oauth2' || authenticationType === 'sso') { _%>
@SecurityScheme(
        name = "oauth2",
        type = io.swagger.v3.oas.annotations.enums.SecuritySchemeType.OAUTH2,
        flows = @io.swagger.v3.oas.annotations.security.OAuthFlows(
                authorizationCode = @io.swagger.v3.oas.annotations.security.OAuthFlow(
                        authorizationUrl = "<%= authenticationType === 'oauth2' ? oauth2IssuerUri : ssoIssuerUri %>/protocol/openid-connect/auth",
                        tokenUrl = "<%= authenticationType === 'oauth2' ? oauth2IssuerUri : ssoIssuerUri %>/protocol/openid-connect/token"
                )
        )
)
<%_ } _%>
<%_ if (authenticationType === 'jwt') { _%>
@SecurityScheme(
        name = "bearerAuth",
        type = io.swagger.v3.oas.annotations.enums.SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        scheme = "bearer"
)
<%_ } _%>
<%_ if (authenticationType === 'basic') { _%>
@SecurityScheme(
        name = "basicAuth",
        type = io.swagger.v3.oas.annotations.enums.SecuritySchemeType.HTTP,
        scheme = "basic"
)
<%_ } _%>
class SwaggerConfig {}
