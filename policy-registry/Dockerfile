# BUILD TOOL - maven
FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /app

COPY hearth-auth-common /hearth-auth-common
RUN mvn -q -f /hearth-auth-common/pom.xml install -DskipTests

COPY policy-registry/pom.xml .

RUN mvn dependency:go-offline -B # caching the dependencies on install

COPY policy-registry/src ./src
COPY proto /proto

RUN mvn clean package -DskipTests # packaging the code into .jar

# RUNTIME - JDK
FROM eclipse-temurin:21-jdk AS runner

WORKDIR /app

COPY --from=builder ./app/target/policy-registry-0.0.1-SNAPSHOT.jar ./app.jar

EXPOSE 9001

ENTRYPOINT ["java", "-Xms256m", "-Xmx512m", "-jar", "app.jar"]