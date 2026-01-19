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
      description: 'Path to the PlantUML file'
    });

    this.option('skip-build', {
      type: Boolean,
      desc: "Skip verification build after generation",
      default: true
    });
  }

  initializing() {
    this.log('Initializing UML to Spring Boot code generator...');
  }

  configuring() {
    this.configOptions = Object.assign({}, this.configOptions, this.config.getAll());
    this.configOptions.formatCode = this.options.formatCode !== false;
    
    if (!this.configOptions.packageName) {
      this.log.error('No Spring Boot project configuration found. Please run the main generator first.');
      process.exit(1);
    }
    
    this.log(`Using package: ${this.configOptions.packageName}`);
    this.log(`Database type: ${this.configOptions.databaseType}`);
    this.log(`Migration tool: ${this.configOptions.dbMigrationTool}`);
  }

  async _parseUML() {
    this.log('Reading UML file...');
    
    const umlFilePath = this.options.umlFile;
    if (!fs.existsSync(umlFilePath)) {
      this.log.error(`UML file not found: ${umlFilePath}`);
      process.exit(1);
    }

    const umlContent = fs.readFileSync(umlFilePath, 'utf8');
    
    this.log('Parsing UML diagram...');
    this.log('UML Content preview:', umlContent.substring(0, 200));
    
    try {
      this.entities = await this.umlParser.parseFile(umlContent);
      this.log(`Found ${this.entities.length} entities`);
      
      if (this.entities.length > 0) {
        this.entities.forEach(entity => {
          this.log(`  - ${entity.name} with ${entity.attributes.length} attributes`);
        });
      } else {
        this.log.warn('No entities were parsed from the UML file');
      }
    } catch (error) {
      this.log.error(`Failed to parse UML: ${error.message}`);
      this.log.error(error.stack);
      process.exit(1);
    }
  }

  async default() {
    await this._parseUML();
  }

  writing() {
    if (!this.entities || this.entities.length === 0) {
      this.log.error('No entities found to generate');
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
        doesNotSupportDatabaseSequences: this.configOptions.databaseType === 'mysql',
        _: _ 
      };

      this.log(`Generating code for entity: ${entity.name}`);

      this._generateAppCode(entityConfig);
      this._generateDbMigrationConfig(entityConfig);
    });
  }

  end() {
    if (!this.entities || this.entities.length === 0) {
      return;
    }

    if(this.configOptions.formatCode !== false) {
      this._formatCode(this.configOptions, null);
    }
    
    if(!this.options['skip-build']) {
      this._verifyBuild(this.configOptions, null);
    }

    this.log('✅ Code generation completed successfully!');
    this.log(`Generated ${this.entities.length} entities with repositories, services, and controllers.`);
    this.log('\nEntities created:');
    this.entities.forEach(entity => {
      this.log(`  - ${entity.name} (${entity.attributes.length} attributes)`);
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

    const testJavaTemplates = [
      {src: 'web/controllers/ControllerTest.java', dest: 'web/controllers/'+configOptions.entityName+'ControllerTest.java'},
      {src: 'web/controllers/ControllerIT.java', dest: 'web/controllers/'+configOptions.entityName+'ControllerIT.java'},
      {src: 'services/ServiceTest.java', dest: 'services/'+configOptions.entityName+'ServiceTest.java'},
    ];
    this.generateTestJavaCode(configOptions, testJavaTemplates);
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
};
