package <%= packageName_%>.enums;

public enum <%= enumName_%> { <% enumValues.forEach(function(value, index) { %> <%= value_%><%= index < enumValues.length - 1 ? ',' : ''%><% });%> }