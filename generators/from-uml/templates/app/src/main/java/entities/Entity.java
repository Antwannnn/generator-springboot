package <%= packageName_%>.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
<%_ if (entity.attributes.some(attr => attr.javaType === 'LocalDate' || attr.javaType === 'LocalDateTime')) { _%>
import java.time.*;
<%_ } _%>
<%_ if (entity.attributes.some(attr => attr.javaType === 'BigDecimal')) { _%>
import java.math.BigDecimal;
<%_ } _%>
<%_ enums.forEach(function(currentEnum) { _%>
<%_ if(entity.attributes.some(attr => attr.javaType === currentEnum.name)) { _%>
import <%= packageName_%>.enums.<%= currentEnum.name_%>;
<%_ } _%>
<%_ }); _%>
<%_ if (entity.relationships && entity.relationships.length > 0) { _%>
import java.util.List;
import java.util.ArrayList;
<%_ } _%>

@Entity
@Table(name = "<%= entity.tableName_%>")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class <%= entityName_%> {
<% entity.attributes.forEach(function(attr) {%>
<%_if (attr.isId) {_%>
    @Id
<%_if (entity.isIdGenerated && !doesNotSupportDatabaseSequences) {_%>
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "<%= entity.tableName_%>_id_seq_gen")
    @SequenceGenerator(name = "<%= entity.tableName_%>_id_seq_gen", sequenceName = "<%= entity.tableName_%>_id_seq")
<%_} else if (entity.isIdGenerated) {_%>
    @GeneratedValue(strategy = GenerationType.IDENTITY)
<%_}_%>
<%_} else {_%>
    @Column(name = "<%= attr.columnName_%>"<%_if (!attr.nullable) {_%>, nullable = false<%_}_%><%_if (attr.unique) {_%>, unique = true<%_}_%><%_if (attr.length) {_%>, length = <%= attr.length_%><%_}_%>)
<%_}_%>
<%_if (enums.map(currentEnum => currentEnum.name).includes(attr.javaType)) {_%>
    @Enumerated(EnumType.STRING)
<%_}_%>
    private <%= attr.javaType %> <%= attr.name%>;
<%_});_%>
<%_if (entity.relationships && entity.relationships.length > 0) {_%>
<%entity.relationships.forEach(function(rel) {%>
    @<%= rel.type %><%if (rel.mappedBy) {%>(mappedBy = "<%= rel.mappedBy %>", fetch = FetchType.<%= rel.fetchType %>)<%} else if (rel.type === 'ManyToOne' || rel.type === 'OneToOne') {%>
    @JoinColumn(name = "<%= _.snakeCase(rel.fieldName) %>_id")<%}%>
    private <%- (rel.type === 'OneToMany' || rel.type === 'ManyToMany') ? 'List<' + rel.target + '>' : rel.target %> <%= rel.fieldName %><% if (rel.type === 'OneToMany' || rel.type === 'ManyToMany') { %> = new ArrayList<>()<% } %>;
<%_});_%>
<%_}_%>
}
