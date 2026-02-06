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

### Bonnes pratiques pour maximiser l'interprétabilité d'un diagramme UML
Le parsing offert par le générateur ne peut pas être exhaustif au vu de la complexité et du grand nombre des possibilités et de libertés offertes par le langage UML en général. Pour cette raison il y'a pour ce générateur des bonnes pratiques UML à respecter pour maximiser les chances d'obtenir un résultat cohérent avec l'entrée.

Le générateur est sensible aux sauts de ligne, un diagramme UML inline produira un résultat erroné.

Les notes sont ignorées.

#### Début et fin

Un diagramme UML doit commencer par la ligne ```@startuml``` et finir par la ligne ```@enduml```

#### Entitées
- Les entités doivent être modélisées sous le mot clé "class" suivi du nom de la classe et d'une accolade ouvrante.
- Chaque attribut déclaré doit suivre le modèle "+" ou "-" pour la visibilité suivi du nom (collés) avec ensuite ":" et le type dont ceux supportés sont listés plus haut.

Exemple
```uml
class Person {
  + id: long
  + name: string
  + age: int
}
``` 

#### Enums
- Les déclarations d'enums suivent le même schéma que les classes à savoir le mot clé "enum" suivi du nom de l'enum et d'une accolade ouvrante.
- Les valeurs de l'enum sont à lister sous la forme de valeurs simples sans types ni visibilité.

Exemple
```uml
enum Status {
  ACTIVE
  INACTIVE
  DELETED
  ARCHIVED
}
```

#### Relations
- Les relations doivent adopter la forme 'S "SC" D "TC" T : N' où :
  - S = Source
  - SC = Source Cardinality ("1", "0..*", "1..*" etc...)
  - D = Direction (-- --> <--)
  - TC = Target Cardinality (1, 0..*, * 1..* etc...)
  - T = Target
  - N = Name (de la relation / attribut associé dans le code)

Exemple
```uml
Product "0" --> "1..*" Person
Product "*" -- "*" Article
Shop "1" -- "1" Company
``` 

#### Exemple de diagramme complet

Entrée :
```uml
@startuml

class Person {
  +id : int
  +name : String
}

class Company {
  +id : int
  +name : String
  +address : String
  +foundedYear : int
  +status : Status
}

enum Status {
 PUBLIC
 PRIVATE
}

Person "*" -- "1" Company : works_for

@enduml
```

Sortie(s) :

Classe (entité) "Person" :
```java
package fr.infotel.testapp.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.util.List;
import java.util.ArrayList;

@Entity
@Table(name = "person")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Person{

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "person_id_seq_gen")
    @SequenceGenerator(name = "person_id_seq_gen", sequenceName = "person_id_seq")
    private Integer id;

    @Column(name = "name", length = 255)
    private String name;

    @ManyToOne
    @JoinColumn(name = "works_for_id")
    private Company worksFor;
}
```

Classe (entité) "Company" :
```java
@Entity
@Table(name = "company")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Company{

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "company_id_seq_gen")
    @SequenceGenerator(name = "company_id_seq_gen", sequenceName = "company_id_seq")
    private Integer id;

    @Column(name = "name", length = 255)
    private String name;

    @Column(name = "address", length = 255)
    private String address;

    @Column(name = "founded_year")
    private Integer foundedYear;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private Status status;

    @OneToMany(mappedBy = "worksFor", fetch = FetchType.LAZY)
    private List<Person> persons = new ArrayList<>();
}
```

Enum "Status" :
```java
public enum Status { 
  PUBLIC, 
  PRIVATE 
}
```



