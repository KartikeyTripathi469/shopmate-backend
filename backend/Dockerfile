# Stage 1: Build environment
FROM maven:3.9.6-eclipse-temurin-17-alpine AS build
WORKDIR /app

# Copy pom.xml and download dependencies to leverage Docker cache
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build the application
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Runtime environment
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Copy the built artifact from the build stage
COPY --from=build /app/target/*.jar app.jar

# Runtime configuration
ENV JAVA_OPTS="-Xms256m -Xmx512m" \
    SERVER_PORT=8080

EXPOSE 8080

# Execute the application
ENTRYPOINT ["sh", "-c", "mkdir -p /app/certs && cp /etc/secrets/certs/public_key.pem /app/certs/public_key.pem 2>/dev/null; cp /etc/secrets/certs/private_key.pem /app/certs/private_key.pem 2>/dev/null; java $JAVA_OPTS -jar app.jar"]