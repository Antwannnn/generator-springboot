package <%= packageName %>.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
<% if (entity.attributes.some(attr => attr.javaType === 'LocalDate' || attr.javaType === 'LocalDateTime')) { %>
import java.time.*;
<% } %>
<% if (entity.attributes.some(attr => attr.javaType === 'BigDecimal')) { %>
import java.math.BigDecimal;
<% } %>
<% if (entity.relationships && entity.relationships.length > 0) { %>
import java.util.List;
import java.util.ArrayList;
<% } %>

@Entity
@Table(name = "<%= entity.tableName %>")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class <%= entityName %> {
<% entity.attributes.forEach(function(attr) { %>
<% if (attr.isId) { %>
    @Id
<% if (entity.isIdGenerated && !doesNotSupportDatabaseSequences) { %>
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "<%= entity.tableName %>_id_seq_gen")
    @SequenceGenerator(name = "<%= entity.tableName %>_id_seq_gen", sequenceName = "<%= entity.tableName %>_id_seq")
<% } else if (entity.isIdGenerated) { %>
    @GeneratedValue(strategy = GenerationType.IDENTITY)
<% } %>
<% } else { %>
    @Column(name = "<%= attr.columnName %>"<% if (!attr.nullable) { %>, nullable = false<% } %><% if (attr.unique) { %>, unique = true<% } %><% if (attr.length) { %>, length = <%= attr.length %><% } %>)
<% } %>
    private <%= attr.javaType %> <%= attr.name %>;
<% }); %>
<% if (entity.relationships && entity.relationships.length > 0) { %>

<% entity.relationships.forEach(function(rel) { %>
    @<%= rel.type %><% if (rel.mappedBy) { %>(mappedBy = "<%= rel.mappedBy %>", fetch = FetchType.<%= rel.fetchType %>)<% } else if (rel.type === 'ManyToOne' || rel.type === 'OneToOne') { %>
    @JoinColumn(name = "<%= _.snakeCase(rel.fieldName) %>_id")<% } %>
    private <%- (rel.type === 'OneToMany' || rel.type === 'ManyToMany') ? 'List<' + rel.target + '>' : rel.target %> <%= rel.fieldName %>;
<% }); %>
<% } %>
}
