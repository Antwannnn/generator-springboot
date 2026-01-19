"use strict";
const _ = require('lodash');

class UMLParser {
  async parseFile(umlContent) {
    try {
      console.log('Starting manual UML parsing...');
      const parsed = this.parseManually(umlContent);
      console.log('Parsed result:', JSON.stringify(parsed, null, 2));
      return this.transformToEntityModel(parsed);
    } catch (error) {
      console.error('Parser error:', error);
      throw new Error(`Failed to parse UML: ${error.message}`);
    }
  }

  /*
  Avec cette fonction on parse manuellement les fichiers UML de sorte
  à avoir le contrôle sur le processus de parsing.
  */
  parseManually(umlContent) {
    const entities = [];
    const relationships = [];
    const lines = umlContent.split('\n');
    let currentClass = null;
    let inClass = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      if (!line || line.startsWith('\'') || line.startsWith('//')) {
        continue;
      }

      if (line.startsWith('@')) {
        continue;
      }

      const classMatch = line.match(/^\s*class\s+(\w+)(?:\s+<<(\w+)>>)?\s*\{?/);
      if (classMatch) {
        currentClass = {
          type: 'class',
          name: classMatch[1],
          stereotype: classMatch[2] || null,
          members: []
        };
        inClass = true;
        console.log('Found class:', currentClass.name);
        continue;
      }

      if (line === '}' && inClass) {
        if (currentClass) {
          entities.push(currentClass);
          console.log('Completed class:', currentClass.name, 'with', currentClass.members.length, 'members');
        }
        currentClass = null;
        inClass = false;
        continue;
      }

      // Gestion des cardinalités
      const relationMatch = line.match(/(\w+)\s+"([^"]+)"\s*(<?-{1,2}>?|\*-{1,2}\*?|o-{1,2}o?)\s+"([^"]+)"\s*(\w+)(?:\s*:\s*(.+))?/);
      if (relationMatch) {
        const [, sourceEntity, sourceCardinality, relType, targetCardinality, targetEntity, label] = relationMatch;
        
        relationships.push({
          source: sourceEntity,
          sourceCardinality: sourceCardinality.trim(),
          target: targetEntity,
          targetCardinality: targetCardinality.trim(),
          relationType: relType,
          label: label ? label.trim() : null
        });
        console.log('Found relationship:', sourceEntity, `"${sourceCardinality}"`, relType, `"${targetCardinality}"`, targetEntity, label ? `: ${label}` : '');
        continue;
      }

      // Parse les attributs
      if (inClass && currentClass && line) {
        let attrMatch = line.match(/^([+\-#~])?\s*(\w+)\s*:\s*(\w+)(?:\s+<<([^>]+)>>)?(?:\s+\{([^}]+)\})?/);
        
        if (!attrMatch) {
          attrMatch = line.match(/^([+\-#~])?\s*(\w+)\s+(\w+)(?:\s+<<([^>]+)>>)?(?:\s+\{([^}]+)\})?/);
          if (attrMatch) {
            const [, visibility, type, name, stereotype, constraints] = attrMatch;
            attrMatch = [line, visibility, name, type, stereotype, constraints];
          }
        }

        if (attrMatch) {
          const [, visibility, name, type, stereotype, constraints] = attrMatch;
          const member = {
            type: 'attribute',
            visibility: visibility || '+',
            name: name,
            dataType: type,
            stereotype: stereotype || null,
            constraints: constraints ? constraints.split(',').map(c => c.trim()) : []
          };
          currentClass.members.push(member);
          console.log('Found attribute:', name, ':', type);
        }
      }
    }

    return { entities, relationships };
  }

  transformToEntityModel(umlData) {
    console.log('Transforming UML data to entity model...');
    
    const entities = [];
    const { entities: classEntities, relationships } = umlData;

    if (!Array.isArray(classEntities)) {
      console.warn('Expected array but got:', typeof classEntities);
      return entities;
    }

    // On crée les entités
    const entityMap = new Map();
    classEntities.forEach(item => {
      console.log('Processing item:', item.type, item.name);
      
      if (item.type === 'class') {
        const entity = {
          name: item.name,
          tableName: this.toSnakeCase(item.name),
          attributes: this.parseAttributes(item.members || []),
          relationships: [],
          isIdGenerated: this.hasGeneratedId(item.members || [])
        };
        entities.push(entity);
        entityMap.set(item.name, entity);
        console.log(`Created entity: ${entity.name} with ${entity.attributes.length} attributes`);
      }
    });

    // On doit créer les relations en se basant sur la cardinalité
    if (relationships && Array.isArray(relationships)) {
      relationships.forEach(rel => {
        const sourceEntity = entityMap.get(rel.source);
        const targetEntity = entityMap.get(rel.target);
        
        if (sourceEntity && targetEntity) {
          // Determine la relation selon la cardinalité
          const sourceRelType = this.determineRelationTypeFromCardinality(rel.sourceCardinality, rel.targetCardinality);
          const targetRelType = this.determineRelationTypeFromCardinality(rel.targetCardinality, rel.sourceCardinality);
          
          const sourceRelation = {
            type: sourceRelType,
            target: rel.target,
            fieldName: rel.label ? _.camelCase(rel.label) : this.pluralizeIfNeeded(_.camelCase(rel.target), sourceRelType),
            mappedBy: sourceRelType === 'OneToMany' ? _.camelCase(rel.source) : null,
            fetchType: 'LAZY',
            cascade: this.inferCascade(sourceRelType)
          };
          sourceEntity.relationships.push(sourceRelation);
          console.log(`Added relationship: ${sourceEntity.name}.${sourceRelation.fieldName} -> ${targetEntity.name} (@${sourceRelation.type})`);
          
          if (targetRelType !== 'None') {
            const targetRelation = {
              type: targetRelType,
              target: rel.source,
              fieldName: _.camelCase(rel.source),
              mappedBy: null, 
              fetchType: 'LAZY',
              cascade: []
            };
            targetEntity.relationships.push(targetRelation);
            console.log(`Added inverse relationship: ${targetEntity.name}.${targetRelation.fieldName} -> ${sourceEntity.name} (@${targetRelation.type})`);
          }
        }
      });
    }

    return entities;
  }

  determineRelationTypeFromCardinality(sourceCard, targetCard) {
    const isSourceMany = sourceCard.includes('*') || sourceCard.includes('..');
    const isTargetMany = targetCard.includes('*') || targetCard.includes('..');
    
    if (!isSourceMany && !isTargetMany) {
      return 'OneToOne';
    } else if (!isSourceMany && isTargetMany) {
      return 'OneToMany';
    } else if (isSourceMany && !isTargetMany) {
      return 'ManyToOne';
    } else {
      return 'ManyToMany';
    }
  }

  pluralizeIfNeeded(name, relType) {
    if (relType === 'OneToMany' || relType === 'ManyToMany') {
      return name.endsWith('s') ? name : name + 's';
    }
    return name;
  }

  inferMappedBy(rel, sourceEntity, targetEntity, relType) {
    if (relType === 'OneToMany') {
      return _.camelCase(sourceEntity.name);
    }
    return null;
  }

  inferCascade(relationType) {
    if (relationType === 'OneToMany' || relationType === 'OneToOne') {
      return ['ALL'];
    }
    return [];
  }

  parseAttributes(members) {
    console.log('Parsing attributes from members:', members.length, 'members');
    
    if (!Array.isArray(members)) {
      console.warn('Members is not an array:', members);
      return [];
    }

    return members
      .filter(m => m.type === 'attribute')
      .map(attr => {
        const parsedAttr = {
          name: attr.name,
          type: attr.dataType,
          javaType: this.mapToJavaType(attr.dataType),
          columnName: this.toSnakeCase(attr.name),
          isId: this.isIdField(attr),
          nullable: !this.isRequired(attr),
          unique: this.isUnique(attr),
          length: this.getLength(attr)
        };
        console.log('Parsed attribute:', parsedAttr);
        return parsedAttr;
      });
  }

  mapToJavaType(type) {
    const typeMapping = {
      'string': 'String',
      'int': 'Integer',
      'integer': 'Integer',
      'long': 'Long',
      'boolean': 'Boolean',
      'date': 'LocalDate',
      'localdate': 'LocalDate',
      'datetime': 'LocalDateTime',
      'localdatetime': 'LocalDateTime',
      'timestamp': 'Instant',
      'instant': 'Instant',
      'decimal': 'BigDecimal',
      'bigdecimal': 'BigDecimal',
      'double': 'Double',
      'float': 'Float'
    };
    return typeMapping[type.toLowerCase()] || type;
  }

  isIdField(attr) {
    return attr.name.toLowerCase() === 'id' || 
           (attr.stereotype && attr.stereotype.toLowerCase().includes('id')) ||
           (attr.visibility === '+' && attr.name === 'id');
  }

  isRequired(attr) {
    return attr.constraints.some(c => c.toLowerCase().includes('required') || c.toLowerCase().includes('notnull'));
  }

  isUnique(attr) {
    return attr.constraints.some(c => c.toLowerCase().includes('unique'));
  }

  hasGeneratedId(members) {
    return members.some(m => 
      m.type === 'attribute' && this.isIdField(m)
    );
  }

  toSnakeCase(str) {
    return str
      .replace(/([A-Z])/g, '_$1')
      .toLowerCase()
      .replace(/^_/, '');
  }

  getLength(attr) {
    const maxConstraint = attr.constraints.find(c => c.toLowerCase().includes('max='));
    if (maxConstraint) {
      const match = maxConstraint.match(/max\s*=\s*(\d+)/i);
      if (match) {
        return parseInt(match[1], 10);
      }
    }
    
    return attr.dataType.toLowerCase() === 'string' ? 255 : null;
  }
}

module.exports = UMLParser;
