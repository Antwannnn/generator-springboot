-- liquibase formatted sql
-- changeset author:app id:createTable-<% tableName %>
-- see https://docs.liquibase.com/concepts/changelogs/sql-format.html

create table <%= tableName %> (
    id bigint not null auto_increment,
    <%_ entity.attributes.forEach((attr, index) => { _%>
    <%_ if (!attr.isId) { _%>
    <%= _.snakeCase(attr.name) %> <%= getSqlType(attr.type, databaseType) %><%= attr.required ? ' not null' : '' %><%= attr.unique ? ' unique' : '' %>,
    <%_ } _%>
    <%_ }); _%>
    <%_ const manyToOneRelations = entity.relationships.filter(rel => rel.type === 'ManyToOne'); _%>
    <%_ manyToOneRelations.forEach((rel, index) => { _%>
    <%= _.snakeCase(rel.name) %>_id bigint<%= rel.required ? ' not null' : '' %>,
    <%_ }); _%>
    primary key (id)<%_ if (manyToOneRelations.length > 0) { _%>,
    <%_ manyToOneRelations.forEach((rel, index) => { _%>
    constraint fk_<%= tableName %>_<%= _.snakeCase(rel.targetEntity) %> foreign key (<%= _.snakeCase(rel.name) %>_id) references <%= _.snakeCase(rel.targetEntity) %>(id)<%= index < manyToOneRelations.length - 1 ? ',' : '' %>
    <%_ }); _%>
    <%_ } _%>
);
