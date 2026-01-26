# generator-springboot
Un générateur Yeoman pour générer des projets Springboot en architecture microservices.

## Prérequis
* Node 20+
* JDK 17+

## Installation
```shell
$ npm install -g yo
$ git clone https://github.com/Antwannnn/generator-springboot.git
$ cd generator-springboot/generators
$ npm link
```

## Utilisation
Lancer la commande :

```shell
$ yo springboot
```

et répondez aux questions suivantes :
```
? Quel est le nom de l'applcation (myservice) ?
```

```
? Quel est le nom du package par défaut (com.mycompany.myservice) ?
```

```
? Quel type de base de données voulez-vous utiliser ?
> Postgresql
  MySQL
  MariaDB
```

```
? Quel outil de migration de base de données voulez-vous utiliser ?
> FlywayDB
  Liquibase
  None
```

```
? Sélectionnez les fonctionnalités voulues ?
  ◯ ELK Docker configuration
  ◯ Prometheus, Grafana Docker configuration
  ◯ Localstack Docker configuration
```

```
? Quelle(s) méthode(s) d'authentification souhaitez-vous implémenter ?
  ◯ OAuth2 Resource Server (JWT Validation)
  ◯ OAuth2 Client (Google, Github, Keycloak)
  ◯ JWT (JSON Web Tokens)
```

```
? Quel outil de build souhaitez-vous utiliser ?
> Maven
  Gradle
```

## Fonctionnalités
L'outil génère une application springboot en architecture microservices avec les fonctionnalités suivantes configurées :

* Projet Spring boot avec support pour Maven et Gradle
* Intégration Spring Data & JPA avec une option pour sélectionner la base de données (MySQL, MariaDB, Postgresql)
* Intégration de différents modes d'authentification (OAuth2 Resource Server, OAuth2 Login, JWT)
* Support pour les outils de migration FlywayDB et Liquibase
* Support Spring Cloud AWS avec configuration LocalStack
* Configuration CORS (Cross-Origin Resource Sharing)
* Intégration Swagger UI
* Configuration Spring boot actuator
* Conteneurs de test pour travailler sur l'application en local
* Configuration DockerCompose pour ELK, Prometheus, Grafana
* Configuration GitHub Actions
* Dockerfile
* Jenkinsfile
* SonarQube and JaCoCo based static analysis tools configuration
* Formattage de code en utilisant Spotless et google-java-format
* JUnit 5

### Lancement de l'application
Après la génération vous pouvez lancer le projet en faisant :

```shell
$ cd votre_projet
$ ./mvnw spring-boot:run
```

### Générer une API REST avec CRUD.
Vous pouvez générer une API REST avec des opérations CRUD en utilisant la commande suivante

**IMPORTANT:** Vous devez exécuter la commande ci-dessous en étant dans le dossier du projet.

```shell
$ cd votre_application
$ yo springboot:controller Customer --base-path /api/customers
```

Ce sous-générateur générera suite à cela :

* Une entité JPA
* Un repository Spring Data JPA
* Le service associé à l'entité
* Le controller REST associé à l'entité avec son CRUD
* test unitaires et d'intégration sur le controller REST
* La migration flyway / liquibase

### Générer une API REST avec CRUD + spécifications depuis UML.
Vous pouvez générer une API Rest avec des opérations CRUD mais possédant aussi des attributs personnalisés en fonction du besoin.
Pour cela il faudra passer en paramètre du sous-générateur un diagramme UML permettant d'établir les relations entre les entités.

Pour cela il faut exécuter la commande suivante :

**IMPORTANT:** Vous devez exécuter la commande ci-dessous en étant dans le dossier du projet.

```shell
$ cd votre_application
$ yo springboot:from-uml ./chemin/vers/votre/diagramme.uml
```
Ce sous-générateur générera suite à cela :

* Une entité JPA + ses attributs dans la bonne structure de données
* Les relations entre entitées (in progress)
* L'application de la (OneToMany, ManyToOne, ManyToMany, OneToOne) (in progress)
* Les enums si il y'en a (in progress)
* Un repository Spring Data JPA
* Le service associé à l'entité
* Le controller REST associé à l'entité avec son CRUD
* test unitaires et d'intégration sur le controller REST
* La migration flyway / liquibase 

### Structures de données supportées en UML et leur équivalent
Les structures de données suivantes sont supportées dans le parsing des diagrammes UML

```javascript
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
```