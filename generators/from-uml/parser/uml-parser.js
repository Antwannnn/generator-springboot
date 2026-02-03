"use strict";
const _ = require('lodash');
const { off } = require('process');

class UMLParser {
  async parseFile(umlContent) {
    try {
      console.log('Démarrage de l\'analyse manuelle UML...');
      const parsed = this.parseManually(umlContent);
      console.log('Résultat de l\'analyse:', JSON.stringify(parsed, null, 2));
      return this.transformToEntityModel(parsed);
    } catch (error) {
      console.error('Erreur d\'analyse:', error);
      throw new Error(`Échec de l'analyse UML: ${error.message}`);
    }
  }

  /*
  Avec cette fonction on parse manuellement les fichiers UML de sorte
  à avoir le contrôle sur toute la chaîne.
  */
  parseManually(umlContent) {
    const entities = [];
    const enums = [];
    const relationships = [];
    const lines = umlContent.split('\n');
    let currentClass = null;
    let currentEnum = null;
    let inClass = false;
    let inEnum = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      if (!line || line.startsWith('\'') || line.startsWith('//')) {
        continue;
      }

      if (line.startsWith('@')) {
        continue;
      }

      const enumMatch = line.match(/^\s*enum\s+(\w+)\s*\{?/);
      if (enumMatch) {
        currentEnum = {
          type: 'enum',
          name: enumMatch[1],
          values: []
        };
        inEnum = true;
        console.log('Enum trouvé:', currentEnum.name);
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
        console.log('Classe trouvée:', currentClass.name);
        continue;
      }

      if (line === '}') {
        if (inClass && currentClass) {
          entities.push(currentClass);
          console.log('Classe complétée:', currentClass.name, 'avec', currentClass.members.length, 'membre(s)');
          currentClass = null;
          inClass = false;
        } else if (inEnum && currentEnum) {
          enums.push(currentEnum);
          console.log('Enum complété:', currentEnum.name, 'avec', currentEnum.values.length, 'valeur(s)');
          currentEnum = null;
          inEnum = false;
        }
        continue;
      }

      if (inEnum && currentEnum && line) {
        const enumValue = line.replace(/,\s*$/, '').trim();
        if (enumValue && !enumValue.includes('(')) { 
          currentEnum.values.push(enumValue);
          console.log('Valeur enum trouvée:', enumValue);
        }
        continue;
      }

      const relationMatch = line.match(/(\w+)\s+"([^"]+)"\s*(<?-{1,2}>?|\*-{1,2}\*?|o-{1,2}o?)\s+"([^"]+)"\s*(\w+)(?:\s*:\s*(.+))?/);
      if (relationMatch) {
        const [, sourceEntity, sourceCardinality, relType, targetCardinality, targetEntity, label] = relationMatch;
        
        relationships.push({
          source: sourceEntity,
          sourceCardinality: sourceCardinality.trim(),
          target: targetEntity,
          targetCardinality: targetCardinality.trim(),
          relationType: relType,
          label: label ? label.trim() : null,
        });
        console.log('Relation trouvée:', sourceEntity, `"${sourceCardinality}"`, relType, `"${targetCardinality}"`, targetEntity, label ? `: ${label}` : '');
        continue;
      }

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
          console.log('Attribut trouvé:', name, ':', type);
        }
      }
    }

    return { entities, enums, relationships };
  }

  transformToEntityModel(umlData) {
    console.log('Transformation des données UML en modèle d\'entité...');
    
    const entities = [];
    const enums = [];
    const { entities: classEntities, enums: enumList, relationships } = umlData;

    if (!Array.isArray(classEntities)) {
      console.warn('Tableau d\'entités attendu mais reçu:', typeof classEntities);
      return { entities, enums };
    }

    if (enumList && Array.isArray(enumList)) {
      enumList.forEach(enumItem => {
        const enumModel = {
          name: enumItem.name,
          values: enumItem.values
        };
        enums.push(enumModel);
        console.log(`Enum créé: ${enumModel.name} avec ${enumModel.values.length} valeur(s)`);
      });
    }

    const entityMap = new Map();
    classEntities.forEach(item => {
      console.log('Traitement de l\'élément:', item.type, item.name);
      
      if (item.type === 'class') {
        const entity = {
          name: item.name,
          tableName: this.toSnakeCase(item.name),
          attributes: this.parseAttributes(item.members || [], enums),
          relationships: [],
          isIdGenerated: this.hasGeneratedId(item.members || [])
        };
        entities.push(entity);
        entityMap.set(item.name, entity);
        console.log(`Entité créée: ${entity.name} avec ${entity.attributes.length} attribut(s)`);
      }
    });
    
    if (relationships && Array.isArray(relationships)) {
      relationships.forEach(rel => {
        const sourceEntity = entityMap.get(rel.source);
        const targetEntity = entityMap.get(rel.target);
        
        if (sourceEntity && targetEntity) {
          const sourceRelType = this.determineRelationTypeFromCardinality(
            rel.sourceCardinality,
            rel.targetCardinality
          );
          const targetRelType = this.determineRelationTypeFromCardinality(
            rel.targetCardinality,
            rel.sourceCardinality
          );
          if (sourceRelType !== 'None' && rel.relationType !== '<--') {
            const isCollection = sourceRelType === 'OneToMany' || sourceRelType === 'ManyToMany';
            const sourceRelation = {
              type: sourceRelType,
              target: rel.target,
              fieldName: rel.label
                ? _.camelCase(rel.label)
                : isCollection
                ? this.pluralizeIfNeeded(_.camelCase(rel.target), sourceRelType)
                : _.camelCase(rel.target),
              mappedBy:
                isCollection && rel.relationType === 'bidirectional'
                  ? _.camelCase(rel.source) 
                  : null,
              fetchType: 'LAZY',
              cascade: this.inferCascade(sourceRelType),
            };
            sourceEntity.relationships.push(sourceRelation);
            console.log(
              `Relation ajoutée: ${sourceEntity.name}.${sourceRelation.fieldName} -> ${targetEntity.name} (@${sourceRelation.type})`
            );
          }
          const needsFK = rel.targetCardinality.includes('*');
          if (needsFK && !targetEntity.relationships.some(r => r.type === 'ManyToOne' && r.target === sourceEntity.name)) {
            targetEntity.relationships.push({
              type: 'ManyToOne',
              target: sourceEntity.name,
              fieldName: _.camelCase(sourceEntity.name),
              mappedBy: null,
              fetchType: 'LAZY',
              cascade: []
            });
          }

          if (targetRelType !== 'None' && rel.relationType !== '-->') {
            const isCollection = targetRelType === 'OneToMany' || targetRelType === 'ManyToMany';
            const targetRelation = {
              type: targetRelType,
              target: sourceEntity.name,
              fieldName: isCollection
                ? this.pluralizeIfNeeded(_.camelCase(sourceEntity.name), targetRelType)
                : _.camelCase(sourceEntity.name),
              mappedBy: isCollection && rel.relationType === 'bidirectional'
                ? _.camelCase(rel.target)
                : null,
              fetchType: 'LAZY',
              cascade: this.inferCascade(targetRelType),
            };
            targetEntity.relationships.push(targetRelation);
          }

        }
      });
    }

    return { entities, enums };
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

  parseAttributes(members, enums) {
    console.log('Analyse des attributs depuis les membres:', members.length, 'membre(s)');
    
    if (!Array.isArray(members)) {
      console.warn('Membres n\'est pas un tableau:', members);
      return [];
    }

    return members
      .filter(m => m.type === 'attribute')
      .map(attr => {
        const parsedAttr = {
          name: attr.name,
          type: attr.dataType,
          javaType: this.mapToJavaType(attr.dataType, enums),
          isEnum: this.isEnumType(attr.dataType, enums),
          columnName: this.toSnakeCase(attr.name),
          isId: this.isIdField(attr),
          nullable: !this.isRequired(attr),
          unique: this.isUnique(attr),
          length: this.getLength(attr)
        };
        console.log('Attribut analysé:', parsedAttr);
        return parsedAttr;
      });
  }

  isEnumType(type, enums) {
    if (!enums || !Array.isArray(enums)) return false;
    return enums.some(e => e.name === type);
  }

  mapToJavaType(type, enums) {
    if (this.isEnumType(type, enums)) {
      return type;
    }

    const typeMapping = {
      'string': 'String',
      'int': 'Integer',
      'integer': 'Integer',
      'long': 'Long',
      'boolean': 'Boolean',
      'bool': 'Boolean',
      'date': 'LocalDate',
      'localdate': 'LocalDate',
      'datetime': 'LocalDateTime',
      'localdatetime': 'LocalDateTime',
      'timestamp': 'Instant',
      'instant': 'Instant',
      'decimal': 'BigDecimal',
      'bigdecimal': 'BigDecimal',
      'bigint': 'BigInteger',
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
