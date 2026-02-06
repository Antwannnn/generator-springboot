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
            console.log(`\nTraitement relation: ${rel.source} "${rel.sourceCardinality}" ${rel.relationType} "${rel.targetCardinality}" ${rel.target}`);
            
            const relationType = this.determineRelationTypeFromCardinality(
              rel.sourceCardinality,
              rel.targetCardinality
            );
            
            const direction = this.determineRelationDirection(rel.relationType);
            console.log(`Type de relation: ${relationType}, Direction: ${direction}`);
            
            this.createRelationships(
              sourceEntity,
              targetEntity,
              relationType,
              direction,
              rel
            );
          }
        });
      }

    return { entities, enums };
  }

    /**
   * Détermine le type de relation basé sur les cardinalités
   * @param {string} sourceCard - Cardinalité source (ex: "1", "0..1", "*", "1..*")
   * @param {string} targetCard - Cardinalité cible
   * @returns {string} Type de relation JPA
   */
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

  /**
   * Détermine la direction de la relation basée sur le type de flèche
   * @param {string} arrowType - Type de flèche UML
   * @returns {string} Direction: 'unidirectional', 'bidirectional', 'source-to-target', 'target-to-source'
   */
  determineRelationDirection(arrowType) {
    // --> : unidirectionnelle de source vers target
    if (arrowType === '-->' || arrowType === '->' || arrowType.endsWith('>') && !arrowType.startsWith('<')) {
      return 'source-to-target';
    }
    // <-- : unidirectionnelle de target vers source
    if (arrowType === '<--' || arrowType === '<-' || arrowType.startsWith('<') && !arrowType.endsWith('>')) {
      return 'target-to-source';
    }
    // <--> ou -- : bidirectionnelle
    if (arrowType.includes('<') && arrowType.includes('>')) {
      return 'bidirectional';
    }
    // Par défaut, considérer comme bidirectionnelle pour les associations simples
    return 'bidirectional';
  }

  /**
   * Crée les relations entre entités selon le type et la direction
   */
  createRelationships(sourceEntity, targetEntity, relationType, direction, rel) {
    const label = rel.label ? _.camelCase(rel.label) : null;

    switch (relationType) {
      case 'OneToOne':
        this.createOneToOneRelation(sourceEntity, targetEntity, direction, label);
        break;
      case 'OneToMany':
        this.createOneToManyRelation(sourceEntity, targetEntity, direction, label);
        break;
      case 'ManyToOne':
        this.createManyToOneRelation(sourceEntity, targetEntity, direction, label);
        break;
      case 'ManyToMany':
        this.createManyToManyRelation(sourceEntity, targetEntity, direction, label);
        break;
    }
  }

  /**
   * Crée une relation OneToOne
   */
  createOneToOneRelation(sourceEntity, targetEntity, direction, label) {
    if (direction === 'source-to-target' || direction === 'bidirectional') {
      const fieldName = label || _.camelCase(targetEntity.name);
      sourceEntity.relationships.push({
        type: 'OneToOne',
        target: targetEntity.name,
        fieldName: fieldName,
        mappedBy: null,
        fetchType: 'LAZY',
        cascade: ['ALL'],
        optional: true
      });
      console.log(`  -> ${sourceEntity.name}.${fieldName} (@OneToOne)`);
    }

    if (direction === 'target-to-source' || direction === 'bidirectional') {
      const fieldName = _.camelCase(sourceEntity.name);
      const mappedBy = direction === 'bidirectional' ? (label || _.camelCase(targetEntity.name)) : null;
      targetEntity.relationships.push({
        type: 'OneToOne',
        target: sourceEntity.name,
        fieldName: fieldName,
        mappedBy: mappedBy,
        fetchType: 'LAZY',
        cascade: mappedBy ? [] : ['ALL'],
        optional: true
      });
      console.log(`  -> ${targetEntity.name}.${fieldName} (@OneToOne${mappedBy ? `, mappedBy="${mappedBy}"` : ''})`);
    }
  }

  /**
   * Crée une relation OneToMany
   * Source (1) -> Target (*)
   */
  createOneToManyRelation(sourceEntity, targetEntity, direction, label) {
    if (direction === 'source-to-target' || direction === 'bidirectional') {
      const fieldName = label || this.pluralizeIfNeeded(_.camelCase(targetEntity.name), 'OneToMany');
      const mappedBy = _.camelCase(sourceEntity.name);
      
      sourceEntity.relationships.push({
        type: 'OneToMany',
        target: targetEntity.name,
        fieldName: fieldName,
        mappedBy: mappedBy,
        fetchType: 'LAZY',
        cascade: ['ALL'],
        orphanRemoval: true
      });
      console.log(`  -> ${sourceEntity.name}.${fieldName} (@OneToMany, mappedBy="${mappedBy}")`);

      // Ajouter automatiquement le ManyToOne côté target
      if (!targetEntity.relationships.some(r => r.type === 'ManyToOne' && r.target === sourceEntity.name)) {
        targetEntity.relationships.push({
          type: 'ManyToOne',
          target: sourceEntity.name,
          fieldName: mappedBy,
          mappedBy: null,
          fetchType: 'LAZY',
          cascade: [],
          optional: false
        });
        console.log(`  -> ${targetEntity.name}.${mappedBy} (@ManyToOne) [auto-généré]`);
      }
    }

    if (direction === 'target-to-source') {
      // Dans ce cas, c'est plutôt un ManyToOne de target vers source
      const fieldName = _.camelCase(sourceEntity.name);
      targetEntity.relationships.push({
        type: 'ManyToOne',
        target: sourceEntity.name,
        fieldName: fieldName,
        mappedBy: null,
        fetchType: 'LAZY',
        cascade: [],
        optional: false
      });
      console.log(`  -> ${targetEntity.name}.${fieldName} (@ManyToOne)`);
    }
  }

  createManyToOneRelation(sourceEntity, targetEntity, direction, label) {
    if (direction === 'source-to-target' || direction === 'bidirectional') {
      const fieldName = label || _.camelCase(targetEntity.name);
      sourceEntity.relationships.push({
        type: 'ManyToOne',
        target: targetEntity.name,
        fieldName: fieldName,
        mappedBy: null,
        fetchType: 'LAZY',
        cascade: [],
        optional: false
      });
      console.log(`  -> ${sourceEntity.name}.${fieldName} (@ManyToOne)`);
    }

    if (direction === 'target-to-source' || direction === 'bidirectional') {
      const fieldName = this.pluralizeIfNeeded(_.camelCase(sourceEntity.name), 'OneToMany');
      const mappedBy = label || _.camelCase(targetEntity.name);
      
      targetEntity.relationships.push({
        type: 'OneToMany',
        target: sourceEntity.name,
        fieldName: fieldName,
        mappedBy: mappedBy,
        fetchType: 'LAZY',
        cascade: ['ALL'],
        orphanRemoval: true
      });
      console.log(`  -> ${targetEntity.name}.${fieldName} (@OneToMany, mappedBy="${mappedBy}")`);
    }
  }

  createManyToManyRelation(sourceEntity, targetEntity, direction, label) {
    if (direction === 'source-to-target' || direction === 'bidirectional') {
      const fieldName = label || this.pluralizeIfNeeded(_.camelCase(targetEntity.name), 'ManyToMany');
      sourceEntity.relationships.push({
        type: 'ManyToMany',
        target: targetEntity.name,
        fieldName: fieldName,
        mappedBy: null,
        fetchType: 'LAZY',
        cascade: ['PERSIST', 'MERGE']
      });
      console.log(`  -> ${sourceEntity.name}.${fieldName} (@ManyToMany)`);
    }

    if (direction === 'target-to-source' || direction === 'bidirectional') {
      const fieldName = this.pluralizeIfNeeded(_.camelCase(sourceEntity.name), 'ManyToMany');
      const mappedBy = direction === 'bidirectional' ? (label || this.pluralizeIfNeeded(_.camelCase(targetEntity.name), 'ManyToMany')) : null;
      
      targetEntity.relationships.push({
        type: 'ManyToMany',
        target: sourceEntity.name,
        fieldName: fieldName,
        mappedBy: mappedBy,
        fetchType: 'LAZY',
        cascade: mappedBy ? [] : ['PERSIST', 'MERGE']
      });
      console.log(`  -> ${targetEntity.name}.${fieldName} (@ManyToMany${mappedBy ? `, mappedBy="${mappedBy}"` : ''})`);
    }
  }

  pluralizeIfNeeded(name, relType) {
    if (relType === 'OneToMany' || relType === 'ManyToMany') {
      return name.endsWith('s') ? name : name + 's';
    }
    return name;
  }

    inferCascade(relationType) {
    if (relationType === 'OneToMany' || relationType === 'OneToOne') {
      return ['ALL'];
    }
    if (relationType === 'ManyToMany') {
      return ['PERSIST', 'MERGE'];
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
