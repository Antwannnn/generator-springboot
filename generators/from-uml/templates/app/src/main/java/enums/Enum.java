package <%= packageName %>.enums;

public enum <%= enumName %> {
<% enumValues.forEach(function(value, index) { %>
    <%= value %><%= index < enumValues.length - 1 ? ',' : '' %>
<% }); %>
}