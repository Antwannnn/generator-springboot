package <%= packageName %>.model.request;

import jakarta.validation.constraints.*;
import lombok.Data;
<% if (entity.attributes.some(attr => attr.javaType === 'LocalDate' || attr.javaType === 'LocalDateTime')) { %>
import java.time.*;
<% } %>
<% if (entity.attributes.some(attr => attr.javaType === 'BigDecimal')) { %>
import java.math.BigDecimal;
<% } %>

@Data
public class <%= entityName %>Request {
<% entity.attributes.filter(attr => !attr.isId).forEach(function(attr) { %>
    <%_ if (!attr.nullable) { _%>
    @NotNull(message = "<%= attr.name %> is required")
    <%_ } _%>
    <%_ if (attr.javaType === 'String' && attr.length) { _%>
    @Size(max = <%= attr.length %>, message = "<%= attr.name %> must be less than <%= attr.length %> characters")
    <%_ } _%>
    private <%= attr.javaType %> <%= attr.name %>;
<%_ }); _%>
}
