module.exports = {
    prompting
};

async function prompting() {
    const prompts = [
        {
            type: 'string',
            name: 'appName',
            validate: input =>
                /^([a-z_][a-z0-9_\-]*)$/.test(input)
                    ? true
                    : 'The application name you have provided is not valid',
            message: 'What is the application name?',
            default: 'myservice'
        },
        {
            type: 'string',
            name: 'packageName',
            validate: input =>
                /^([a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*)$/.test(input)
                    ? true
                    : 'The package name you have provided is not a valid Java package name.',
            message: 'What is the default package name?',
            default: 'com.mycompany.myservice'
        },
        {
            type: 'list',
            name: 'databaseType',
            message: 'Which type of database you want to use?',
            choices: [
                {
                    value: 'postgresql',
                    name: 'Postgresql'
                },
                {
                    value: 'mysql',
                    name: 'MySQL'
                },
                {
                    value: 'mariadb',
                    name: 'MariaDB'
                }
            ],
            default: 'postgresql'
        },
        {
            type: 'list',
            name: 'dbMigrationTool',
            message: 'Which type of database migration tool you want to use?',
            choices: [
                {
                    value: 'flywaydb',
                    name: 'FlywayDB'
                },
                {
                    value: 'liquibase',
                    name: 'Liquibase'
                },
                {
                    value: 'none',
                    name: 'None'
                }
            ],
            default: 'flywaydb'
        },
        {
            when: (answers) => answers.dbMigrationTool === 'liquibase',
            type: 'list',
            name: 'dbMigrationFormat',
            message: 'Which format do you want to use for database migrations?',
            choices: [
                {
                    value: 'xml',
                    name: 'XML (like \'001-init.xml\')'
                },
                {
                    value: 'yaml',
                    name: 'YAML (like \'001-init.yaml\')'
                },
                {
                    value: 'sql',
                    name: 'SQL (like \'001-init.sql\')'
                }
            ],
            default: 'xml'
        },
        {
            type: 'checkbox',
            name: 'features',
            message: 'Select the features you want?',
            choices: [
                {
                    value: 'elk',
                    name: 'ELK Docker configuration'
                },
                {
                    value: 'monitoring',
                    name: 'Prometheus, Grafana Docker configuration'
                },
                {
                    value: 'localstack',
                    name: 'Localstack Docker configuration'
                }
            ]
        },
        {
            type: 'checkbox',
            name: 'authenticationTypes',
            message: 'Which authentication methods do you want to implement? (You can select multiple)',
            choices: [
                {
                    value: 'oauth2-resource',
                    name: 'OAuth2 Resource Server (JWT validation)'
                },
                {
                    value: 'oauth2-client',
                    name: 'OAuth2 Client (Google/GitHub/Keycloak login)'
                },
                {
                    value: 'sso',
                    name: 'SSO (Single Sign-On)'
                },
                {
                    value: 'jwt',
                    name: 'JWT (JSON Web Tokens)'
                },
                {
                    value: 'basic',
                    name: 'Basic Authentication'
                }
            ],
            default: []
        },
        {
            when: (answers) => answers.authenticationTypes.includes('oauth2-resource'),
            type: 'string',
            name: 'oauth2IssuerUri',
            message: 'OAuth2 Issuer URI (e.g., https://your-auth-server.com)',
            default: 'https://your-auth-server.com'
        },
        {
            when: (answers) => answers.authenticationTypes.includes('oauth2-client'),
            type: 'checkbox',
            name: 'oauth2Providers',
            message: 'Which OAuth2 providers do you want to support?',
            choices: [
                {
                    value: 'google',
                    name: 'Google'
                },
                {
                    value: 'github',
                    name: 'GitHub'
                },
                {
                    value: 'microsoft',
                    name: 'Microsoft'
                },
                {
                    value: 'keycloak',
                    name: 'Keycloak'
                }
            ],
            default: ['google']
        },
        {
            when: (answers) => answers.authenticationTypes.includes('sso'),
            type: 'string',
            name: 'ssoProvider',
            message: 'SSO Provider (e.g., keycloak, okta, azure)',
            default: 'keycloak'
        },
        {
            when: (answers) => answers.authenticationTypes.includes('sso'),
            type: 'string',
            name: 'ssoIssuerUri',
            message: 'SSO Issuer URI',
            default: 'http://localhost:8080/realms/master'
        },
        {
            type: 'list',
            name: 'buildTool',
            message: 'Which build tool do you want to use?',
            choices: [
                {
                    value: 'maven',
                    name: 'Maven'
                },
                {
                    value: 'gradle',
                    name: 'Gradle'
                }
            ],
            default: 'maven'
        }
    ];

    const answers = await this.prompt(prompts);
    Object.assign(this.configOptions, answers);
    this.configOptions.packageFolder = this.configOptions.packageName.replace(/\./g, '/');
    this.configOptions.features = this.configOptions.features || [];
}
