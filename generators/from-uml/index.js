'use strict';
const BaseGenerator = require('../base-generator');
const constants = require('../constants');
const UMLParser = require('./parser/uml-parser');
const fs = require('fs');
const _ = require('lodash');

module.exports = class extends BaseGenerator {

  constructor(args, opts) {
    super(args, opts);
    this.configOptions = this.options.configOptions || {};
    this.umlParser = new UMLParser();
    
    this.argument('umlFile', {
      type: String,
      required: true,
      description: 'Chemin vers le fichier PlantUML'
    });

    this.option('skip-build', {
      type: Boolean,
      desc: "Ignorer la vérification de build après la génération",
      default: false
    });

    this.option('tests', {
      type: Boolean,
      desc: "Ne pas générer de tests",
      default: true
    });
  }

  initializing() {
    this.log('Initialisation du générateur de code UML vers Spring Boot...');
  }

  configuring() {
    this.configOptions = Object.assign({}, this.configOptions, this.config.getAll());
    this.configOptions.formatCode = this.options.formatCode !== false;
    
    if (!this.configOptions.packageName) {
      this.log.error('Aucune configuration de projet Spring Boot trouvée. Veuillez exécuter le générateur principal d\'abord.');
      process.exit(1);
    }
  }

  async _parseUML() {
    this.log('Lecture du fichier UML...');
    
    const umlFilePath = this.options.umlFile;
    if (!fs.existsSync(umlFilePath)) {
      this.log.error(`Fichier UML introuvable: ${umlFilePath}`);
      process.exit(1);
    }

    const umlContent = fs.readFileSync(umlFilePath, 'utf8');
    
    this.log('Analyse du diagramme UML...');
    this.log('Aperçu du contenu UML:', umlContent.substring(0, 200));
    
    try {
      const result = await this.umlParser.parseFile(umlContent);
      this.entities = result.entities;
      this.enums = result.enums || [];
      
      this.log(`${this.entities.length} entité(s) trouvée(s)`);
      this.log(`${this.enums.length} enum(s) trouvé(s)`);
      
      if (this.entities.length > 0) {
        this.entities.forEach(entity => {
          this.log(`  - ${entity.name} avec ${entity.attributes.length} attribut(s)`);
        });
      }
      
      if (this.enums.length > 0) {
        this.enums.forEach(enumItem => {
          this.log(`  - Enum ${enumItem.name} avec ${enumItem.values.length} valeur(s)`);
        });
      }
    } catch (error) {
      this.log.error(`Échec de l'analyse UML: ${error.message}`);
      this.log.error(error.stack);
      process.exit(1);
    }
  }

  async default() {
    await this._parseUML();
  }

  writing() {
    if (this.enums && this.enums.length > 0) {
      this.enums.forEach(enumItem => {
        this.log(`Génération de l'enum: ${enumItem.name}`);
        this._generateEnum(enumItem);
      });
    }

    if (!this.entities || this.entities.length === 0) {
      this.log.error('Aucune entité trouvée à générer');
      return;
    }

    this.entities.forEach((entity, index) => {
      const entityConfig = {
        ...this.configOptions,
        entityName: entity.name,
        entityVarName: _.camelCase(entity.name),
        tableName: entity.tableName,
        basePath: '/api/' + _.kebabCase(entity.name) + 's',
        entity: entity,
        enums: this.enums,
        doesNotSupportDatabaseSequences: this.configOptions.databaseType === 'mysql',
        _: _,
        getSqlType: this._getSqlType.bind(this)
      };

      this.log(`Génération du code pour l'entité: ${entity.name}`);

      this._generateAppCode(entityConfig);
      this._generateDbMigrationConfig(entityConfig);
    });
  }

  _generateAppCode(configOptions) {
      
    const mainJavaTemplates = [
      {src: 'entities/Entity.java', dest: 'entities/'+configOptions.entityName+'.java'},
      {src: 'mapper/Mapper.java', dest: 'mapper/'+configOptions.entityName+'Mapper.java'},
      {src: 'model/query/FindQuery.java', dest: 'model/query/Find'+configOptions.entityName+'sQuery.java'},
      {src: 'exception/NotFoundException.java', dest: 'exception/'+configOptions.entityName+'NotFoundException.java'},
      {src: 'model/request/Request.java', dest: 'model/request/'+configOptions.entityName+'Request.java'},
      {src: 'model/response/Response.java', dest: 'model/response/'+configOptions.entityName+'Response.java'},
      {src: 'repositories/Repository.java', dest: 'repositories/'+configOptions.entityName+'Repository.java'},
      {src: 'services/Service.java', dest: 'services/'+configOptions.entityName+'Service.java'},
      {src: 'web/controllers/Controller.java', dest: 'web/controllers/'+configOptions.entityName+'Controller.java'},
    ];
    this.generateMainJavaCode(configOptions, mainJavaTemplates);
    console.log('Options tests:', this.options.tests);
    if (this.options.tests) {
      const testJavaTemplates = [
        {src: 'web/controllers/ControllerTest.java', dest: 'web/controllers/'+configOptions.entityName+'ControllerTest.java'},
        {src: 'web/controllers/ControllerIT.java', dest: 'web/controllers/'+configOptions.entityName+'ControllerIT.java'},
        {src: 'services/ServiceTest.java', dest: 'services/'+configOptions.entityName+'ServiceTest.java'},
      ];
      this.generateTestJavaCode(configOptions, testJavaTemplates);
    }
  }

  _generateDbMigrationConfig(configOptions) {
    if(configOptions.dbMigrationTool === 'flywaydb') {
      this._generateFlywayMigration(configOptions);
    }

    if(configOptions.dbMigrationTool === 'liquibase') {
      this._generateLiquibaseMigration(configOptions);
    }
  }

  _generateFlywayMigration(configOptions) {
    const counter = configOptions[constants.KEY_FLYWAY_MIGRATION_COUNTER] + 1;
    let vendor = configOptions.databaseType;
    const scriptTemplate = configOptions.doesNotSupportDatabaseSequences ?
      "V1__new_table_no_seq.sql" : "V1__new_table_with_seq.sql";

    this.renderTemplate(
      this.templatePath('app/src/main/resources/db/migration/flyway/'+scriptTemplate),
      this.destinationPath('src/main/resources/db/migration/'+vendor+
        '/V'+counter+'__create_'+configOptions.tableName+'_table.sql'),
      configOptions
    );
    
    const flywayMigrantCounter = {
      [constants.KEY_FLYWAY_MIGRATION_COUNTER]: counter
    };
    this.config.set(flywayMigrantCounter);
  }

  _generateLiquibaseMigration(configOptions) {
    const dbFmt = configOptions.dbMigrationFormat;
    const counter = configOptions[constants.KEY_LIQUIBASE_MIGRATION_COUNTER] + 1;
    const scriptTemplate = configOptions.doesNotSupportDatabaseSequences ?
      `01-new_table_no_seq.${dbFmt}` : `01-new_table_with_seq.${dbFmt}`;
    
    this.renderTemplate(
      this.templatePath('app/src/main/resources/db/migration/liquibase/changelog/'+scriptTemplate),
      this.destinationPath('src/main/resources/db/changelog/migration/0'+counter+'-create_'+configOptions.tableName+'_table.'+dbFmt),
      configOptions
    );
    
    const liquibaseMigrantCounter = {
      [constants.KEY_LIQUIBASE_MIGRATION_COUNTER]: counter
    };
    this.config.set(liquibaseMigrantCounter);
  }

  _generateEnum(enumItem) {
    const enumConfig = {
      ...this.configOptions,
      enumName: enumItem.name,
      enumValues: enumItem.values,
      _: _
    };

    this.renderTemplate(
      this.templatePath('app/src/main/java/enums/Enum.java'),
      this.destinationPath(`src/main/java/${this.configOptions.packageFolder}/enums/${enumItem.name}.java`),
      enumConfig
    );
  }

  _getSqlType(javaType, databaseType) {
    if (this.enums && this.enums.some(e => e.name === javaType)) {
      return databaseType === 'postgresql' ? 'varchar(255)' : 'varchar(255)';
    }

    const typeMap = {
      'String': databaseType === 'postgresql' ? 'varchar(255)' : 'varchar(255)',
      'Integer': 'integer',
      'int': 'integer',
      'Long': 'bigint',
      'long': 'bigint',
      'Boolean': databaseType === 'postgresql' ? 'boolean' : 'tinyint(1)',
      'boolean': databaseType === 'postgresql' ? 'boolean' : 'tinyint(1)',
      'LocalDate': 'date',
      'LocalDateTime': databaseType === 'postgresql' ? 'timestamp' : 'datetime',
      'LocalTime': 'time',
      'Instant': databaseType === 'postgresql' ? 'timestamp' : 'datetime',
      'ZonedDateTime': databaseType === 'postgresql' ? 'timestamp with time zone' : 'datetime',
      'BigDecimal': 'decimal(19,2)',
      'Double': databaseType === 'postgresql' ? 'double precision' : 'double',
      'double': databaseType === 'postgresql' ? 'double precision' : 'double',
      'Float': databaseType === 'postgresql' ? 'real' : 'float',
      'float': databaseType === 'postgresql' ? 'real' : 'float',
      'BigInteger': 'bigint',
      'Byte': 'tinyint',
      'byte': 'tinyint',
      'Short': 'smallint',
      'short': 'smallint',
      'UUID': databaseType === 'postgresql' ? 'uuid' : 'varchar(36)',
      'byte[]': databaseType === 'postgresql' ? 'bytea' : 'blob',
      'Blob': 'blob',
      'Clob': 'text'
    };

    return typeMap[javaType] || 'varchar(255)';
  }
};
