const { type } = require('os');

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
                    : 'Le nom de l\'application que vous avez fourni n\'est pas valide',
            message: 'Quel est le nom de l\'application ?',
            default: 'myservice'
        },
        {
            type: 'string',
            name: 'packageName',
            validate: input =>
                /^([a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*)$/.test(input)
                    ? true
                    : 'Le nom de package que vous avez fourni n\'est pas un nom de package Java valide.',
            message: 'Quel est le nom de package par défaut ?',
            default: 'com.mycompany.myservice'
        },
        {
            type: 'list',
            name: 'databaseType',
            message: 'Quel type de base de données voulez-vous utiliser ?',
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
            message: 'Quel outil de migration de base de données souhaitez-vous utiliser ?',
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
            message: 'Quel format souhaitez-vous utiliser pour les migrations de base de données ?',
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
            message: 'Selectionnez les fonctionnalités voulues ?',
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
            message: 'Quelle(s) méthode(s) d\'authentification souhaitez-vous implémenter ? (Vous pouvez en sélectionner plusieurs)',
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
                    value: 'jwt',
                    name: 'JWT (JSON Web Tokens)'
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
            message: 'Quel provider OAuth2 souhaitez-vous utiliser ?',
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
            when: (answers) => answers.authenticationTypes.includes('jwt'),
            type: 'string',
            name: 'jwtSecret',
            message: 'JWT Secret (utilisé pour signer les tokens)',
            default: generateSigningSecret()
        },
        { when: (answers) => answers.authenticationTypes.includes('jwt'),
            type: 'number',
            name: 'jwtExpiration',
            message: 'JWT Expiration Time (en millisecondes)',
            default: 86400000
        },
        {
            type: "checkbox",
            name: "loggingTypes",
            message: "Quel type de logging souhaitez-vous ajouter ?",
            choices: [
                {
                    value: 'security',
                    name: 'Security'
                },
                {
                    value: 'performance',
                    name: 'Performance'
                },
            ]
        },
        {
            type: 'list',
            name: 'buildTool',
            message: 'Quel outil de build souhaitez-vous utiliser ?',
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

async function generateSigningSecret() {
    const crypto = require('crypto');
    const {promisify} = require('util');
    const randomBytesAsync = promisify(crypto.randomBytes);
    return (await randomBytesAsync(32)).toString('base64');
}
