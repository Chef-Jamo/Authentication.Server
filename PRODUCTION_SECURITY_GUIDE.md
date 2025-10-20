# Production Deployment Security Guide

## Pre-Deployment Security Checklist

### 1. Environment Configuration

#### JWT Configuration

```json
{
  "Jwt": {
    "Secret": "[GENERATE-STRONG-32+-CHAR-SECRET]",
    "Issuer": "your-production-domain.com",
    "Audience": "your-production-client"
  }
}
```

- [ ] Generate a cryptographically secure JWT secret (32+ characters)
- [ ] Never use the default/example JWT secret in production
- [ ] Use Azure Key Vault or similar for secret management
- [ ] Set proper issuer and audience values

#### Database Configuration

```json
{
  "UseInMemoryDatabase": false,
  "ConnectionStrings": {
    "DefaultConnection": "Host=[DB_HOST];Database=[DB_NAME];Username=[DB_USER];Password=[SECURE_PASSWORD];SSL Mode=Require;"
  }
}
```

- [ ] Set `UseInMemoryDatabase` to `false`
- [ ] Use secure, unique database credentials
- [ ] Enable SSL/TLS for database connections
- [ ] Consider using managed database services

#### CORS Configuration

- [ ] Replace `AllowAll` policy with specific origins
- [ ] Use HTTPS-only origins in production
- [ ] Limit to necessary HTTP methods and headers

### 2. HTTPS Configuration

#### Certificate Setup

- [ ] Configure valid TLS certificate (not self-signed)
- [ ] Enable HSTS (configured automatically by SecurityMiddleware)
- [ ] Consider certificate pinning for mobile clients

#### URL Configuration

```json
{
  "ASPNETCORE_URLS": "https://0.0.0.0:443",
  "ASPNETCORE_HTTPS_PORT": "443"
}
```

### 3. Environment Variables

Set these environment variables in production:

```bash
# Required
ASPNETCORE_ENVIRONMENT=Production
Jwt__Secret=[YOUR-SECURE-JWT-SECRET]
ConnectionStrings__DefaultConnection=[YOUR-DB-CONNECTION]

# Optional but recommended
ASPNETCORE_URLS=https://0.0.0.0:443
ASPNETCORE_HTTPS_PORT=443
```

### 4. Application Settings Override

Create `appsettings.Production.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Auth.Service.Project": "Information"
    }
  },
  "UseInMemoryDatabase": false,
  "DetailedErrors": false,
  "Swagger": {
    "Enabled": false
  }
}
```

## Security Hardening

### 1. Reverse Proxy Configuration (Nginx/IIS)

#### Nginx Configuration Example

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;

    # Security Headers (additional to application headers)
    add_header X-Real-IP $remote_addr;
    add_header X-Forwarded-For $proxy_add_x_forwarded_for;

    # Rate Limiting (additional to application rate limiting)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    location / {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 2. Firewall Configuration

- [ ] Open only necessary ports (443 for HTTPS, 80 for redirect)
- [ ] Restrict database access to application servers only
- [ ] Consider using Azure NSG or AWS Security Groups
- [ ] Implement DDoS protection at infrastructure level

### 3. Monitoring & Logging

#### Structured Logging Setup

Consider integrating with:

- Azure Application Insights
- AWS CloudWatch
- Elasticsearch + Kibana
- Serilog with external providers

#### Security Monitoring

- [ ] Set up alerts for multiple failed login attempts
- [ ] Monitor rate limiting violations
- [ ] Track suspicious IP addresses
- [ ] Monitor configuration validation failures
- [ ] Set up automated incident response

## Container Deployment (Docker)

### Dockerfile Security Best Practices

```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

# Create non-root user
RUN adduser --disabled-password --gecos "" --uid 1000 appuser

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["Auth.Service.Project/Auth.Service.Project.csproj", "Auth.Service.Project/"]
RUN dotnet restore "Auth.Service.Project/Auth.Service.Project.csproj"
COPY . .
WORKDIR "/src/Auth.Service.Project"
RUN dotnet build "Auth.Service.Project.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Auth.Service.Project.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["dotnet", "Auth.Service.Project.dll"]
```

### Kubernetes Security

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: auth-service
          image: your-registry/auth-service:latest
          ports:
            - containerPort: 8080
          env:
            - name: ASPNETCORE_ENVIRONMENT
              value: "Production"
            - name: Jwt__Secret
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: jwt-secret
            - name: ConnectionStrings__DefaultConnection
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: db-connection
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            limits:
              memory: "512Mi"
              cpu: "500m"
            requests:
              memory: "256Mi"
              cpu: "250m"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
```

## Post-Deployment Validation

### 1. Security Configuration Check

- [ ] Access `/health` endpoint to verify service is running
- [ ] Verify security configuration validation passes
- [ ] Check all security headers are present in responses
- [ ] Confirm rate limiting is functional

### 2. Security Testing

- [ ] Verify HTTPS is enforced
- [ ] Test rate limiting on auth endpoints
- [ ] Confirm JWT tokens are properly validated
- [ ] Test password strength requirements
- [ ] Verify security headers are present

### 3. Performance Testing

- [ ] Load test authentication endpoints
- [ ] Monitor memory usage (especially for rate limiting and blacklists)
- [ ] Test auto-unlock background service

## Maintenance

### Regular Security Tasks

#### Weekly

- [ ] Review security audit logs
- [ ] Check for failed authentication patterns
- [ ] Monitor rate limiting effectiveness

#### Monthly

- [ ] Update dependency packages
- [ ] Review security configurations
- [ ] Update common password lists

#### Quarterly

- [ ] Security assessment and penetration testing
- [ ] Review and update security policies
- [ ] Audit user access patterns

### Incident Response

#### Suspected Breach

1. Enable global token blacklisting for affected users
2. Force password reset for compromised accounts
3. Review audit logs for attack patterns
4. Update security rules if needed

#### DDoS Attack

1. Review rate limiting effectiveness
2. Implement additional IP blocking if needed
3. Scale application instances if necessary
4. Contact infrastructure provider for additional protection

## Compliance Considerations

### GDPR Compliance

- Audit logs contain personal data (email addresses, IP addresses)
- Implement data retention policies
- Provide user data export capabilities
- Consider data anonymization for long-term logs

### Security Standards

- Follow OWASP Top 10 guidelines
- Implement NIST Cybersecurity Framework controls
- Consider ISO 27001 compliance requirements
- Regular security audits and assessments

## Emergency Contacts

Maintain contact information for:

- Security incident response team
- Infrastructure providers
- Certificate authorities
- Database administrators
- Key stakeholders

---

Remember: Security is an ongoing process, not a one-time implementation. Regular reviews and updates are essential for maintaining a secure authentication service.
