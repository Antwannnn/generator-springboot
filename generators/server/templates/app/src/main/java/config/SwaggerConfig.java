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
        servers = @Server(url = "/")<%_ if (authenticationTypes && authenticationTypes.length > 0) { _%>,
        security = @SecurityRequirement(name = "<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>oauth2<%_ } else if (authenticationTypes.includes('jwt')) { _%>bearerAuth<%_ } _%>")<%_ } _%>)
<%_ if (authenticationTypes && authenticationTypes.includes('oauth2-resource')) { _%>
@SecurityScheme(
        name = "oauth2",
        type = io.swagger.v3.oas.annotations.enums.SecuritySchemeType.OAUTH2,
        flows = @io.swagger.v3.oas.annotations.security.OAuthFlows(
                authorizationCode = @io.swagger.v3.oas.annotations.security.OAuthFlow(
                        authorizationUrl = "<%= oauth2IssuerUri %>/protocol/openid-connect/auth",
                        tokenUrl = "<%= oauth2IssuerUri %>/protocol/openid-connect/token"
                )
        )
)
<%_ } _%>
<%_ if (authenticationTypes && authenticationTypes.includes('jwt')) { _%>
@SecurityScheme(
        name = "bearerAuth",
        type = io.swagger.v3.oas.annotations.enums.SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        scheme = "bearer"
)
<%_ } _%>
class SwaggerConfig {}
