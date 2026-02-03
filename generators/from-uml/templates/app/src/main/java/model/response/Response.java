package <%= packageName %>.model.response;

import lombok.Data;
<% if (entity.attributes.some(attr => attr.javaType === 'LocalDate' || attr.javaType === 'LocalDateTime')) { %>
import java.time.*;
<% } %>
<% if (entity.attributes.some(attr => attr.javaType === 'BigDecimal')) { %>
import java.math.BigDecimal;
<% } %>

@Data
public class <%= entityName %>Response {
<% entity.attributes.forEach(function(attr) { _%>
    private <%= attr.javaType %> <%= attr.name %>;
<% }); %>
}
