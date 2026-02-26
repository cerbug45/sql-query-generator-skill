---
name: sql-query-generator
description: Enterprise SQL Generator v4 - Templates, versioning, query signing, compliance audit logging, multi-dialect transpiler
version: 4.0.0
author: cerbug45
license: MIT
tags: sql, security, database, templates, compliance, audit
---

# SQL Query Generator Skill v4.0.0

## Overview

Enterprise-grade SQL query generation with military-grade security. Generate secure, optimized SQL queries from natural language or templates with full audit trails.

**New in v4.0.0:**
- 50+ pre-built secure query templates
- Git-like query versioning
- HMAC query signing for integrity
- Multi-dialect transpiler (PostgreSQL ↔ MySQL ↔ SQL Server ↔ Oracle)
- Comprehensive query analysis (complexity, risk, performance, security scores)
- Schema introspection and validation
- Compliance mode (SOX, GDPR, HIPAA)
- Adaptive rate limiting with trusted users
- Natural language parser

## Installation

```bash
# Clone repository
git clone https://github.com/cerbug45/sql-query-generator.git
cd sql-query-generator

# Use as module
cp sql_query_generator_v4.py /path/to/your/project/
```

**No external dependencies required** for core functionality. Install database drivers only if executing queries.

## Quick Start

```python
from sql_query_generator_v4 import SQLQueryGenerator, DatabaseType, SecurityLevel

# Initialize with strict security
generator = SQLQueryGenerator(
    DatabaseType.POSTGRESQL,
    security_level=SecurityLevel.STRICT,
    enable_audit_log=True
)

# Generate from template (recommended)
query = generator.query_from_template(
    "crud_select_paginated",
    {
        "columns": "user_id, username, email",
        "table": "users",
        "where": "status = 'active'",
        "order_by": "created_at",
        "limit": 50
    },
    user_id="user_123"
)

print(query.sql)
```

## Supported Databases

- ✅ PostgreSQL
- ✅ MySQL / MariaDB
- ✅ SQLite
- ✅ Microsoft SQL Server
- ✅ Oracle Database
- ✅ ClickHouse
- ✅ Snowflake

## Core Capabilities

### 1. Query Generation
- SELECT with JOINs, aggregations, window functions
- INSERT/UPDATE/DELETE with safety checks
- CTEs and subqueries
- DDL statements (CREATE, ALTER, DROP)

### 2. Query Templates (50+ Built-in)
- Authentication (login, register, password reset)
- CRUD operations (safe SELECT, INSERT, UPDATE, DELETE)
- Analytics (aggregations, time-series, cohorts)
- Joins (INNER, LEFT, RIGHT, FULL)
- Reporting (top-N, rankings, summaries)

```python
# Search templates
templates = generator.templates.search_templates("select")
templates = generator.templates.search_templates("", category="analytics")
templates = generator.templates.search_templates("", tags=["security"])

# List categories
categories = generator.templates.list_categories()
```

### 3. Query Versioning
```python
# Create version
version = generator.versioning.create_version(
    query_id="user_lookup",
    query=query,
    created_by="developer_1",
    changes="Initial version"
)

# Approve version
generator.versioning.approve_version("user_lookup", "1.0.0", "tech_lead")

# Get history
history = generator.versioning.get_version_history("user_lookup")

# Diff versions
diff = generator.versioning.diff_versions("user_lookup", "1.0.0", "2.0.0")
```

### 4. Query Signing
```python
# Sign for integrity
signature = generator.sign_query(query)

# Verify later
is_valid = generator.verify_query(query, signature)
```

### 5. Query Analysis
```python
analysis = generator.analyze_query(query)

print(f"Complexity: {analysis.complexity_score}/100")
print(f"Risk: {analysis.risk_score}/100 ({analysis.risk_level.value})")
print(f"Performance: {analysis.performance_score}/100")
print(f"Security: {analysis.security_score}/100")
print(f"Recommendations: {analysis.recommendations}")
```

### 6. Multi-Dialect Transpiler
```python
# Generate for PostgreSQL
query = generator.generate_select_query(...)

# Transpile to SQL Server
transpiled = generator.transpile_query(query, DatabaseType.MSSQL)
```

### 7. Schema Validation
```python
from sql_query_generator_v4 import TableSchema, ColumnSchema

schema = TableSchema(
    name="users",
    columns=[
        ColumnSchema("user_id", "INTEGER", is_primary_key=True),
        ColumnSchema("username", "VARCHAR", max_length=50)
    ]
)

generator.register_schema(schema)
```

## Security Features (MANDATORY)

### Input Validation
```python
from sql_query_generator_v4 import SQLInputValidator

# Validate identifier
table = SQLInputValidator.validate_identifier("users")

# Validate with injection check
value = SQLInputValidator.validate_string("input", check_injection=True)

# Validate email
email = SQLInputValidator.validate_email("user@example.com")

# Validate date
date = SQLInputValidator.validate_date("2024-01-01")

# Validate UUID
uuid = SQLInputValidator.validate_uuid("550e8400-e29b-41d4-a716-446655440000")
```

### Injection Detection
Detects 24+ attack patterns:
- UNION SELECT attacks
- DROP TABLE attempts
- xp_cmdshell execution
- Time-based blind injection
- File operations
- Information schema enumeration

```python
is_injection = SQLInputValidator.detect_injection_attempt("'; DROP TABLE users; --")
# Returns: True
```

### Audit Logging
```python
# Enable compliance mode
generator = SQLQueryGenerator(
    DatabaseType.POSTGRESQL,
    enable_audit_log=True,
    compliance_mode=True  # SOX, GDPR, HIPAA
)

# All queries logged with:
# - Timestamp, user_id, IP
# - Query fingerprint
# - Execution time
# - Result count
```

### Rate Limiting
```python
# Add trusted user (higher limits)
generator.rate_limiter.add_trusted_user("admin")

# Check usage
stats = generator.rate_limiter.get_usage_stats("user_123")
```

### Table Allowlist
```python
generator = SQLQueryGenerator(
    DatabaseType.POSTGRESQL,
    allowed_tables={'users', 'orders', 'products'}
)
# Queries to other tables will be rejected
```

## Best Practices

### ALWAYS Use Parameterized Queries
```python
# ✅ CORRECT
query = "SELECT * FROM users WHERE username = $1"
cursor.execute(query, (username,))

# ❌ NEVER
query = f"SELECT * FROM users WHERE username = '{username}'"
```

### Validate All Inputs
```python
# Whitelist validation
VALID_STATUSES = ['active', 'inactive', 'pending']
if status not in VALID_STATUSES:
    raise ValueError("Invalid status")

# Type validation
if not isinstance(user_id, int):
    raise TypeError("user_id must be integer")
```

### Use Templates When Possible
Templates are pre-validated and security-audited:
```python
query = generator.query_from_template("auth_login", {...})
```

### Enable Audit Logging for Production
```python
generator = SQLQueryGenerator(
    DatabaseType.POSTGRESQL,
    enable_audit_log=True,
    compliance_mode=True
)
```

## Configuration

```python
generator = SQLQueryGenerator(
    database_type=DatabaseType.POSTGRESQL,
    security_level=SecurityLevel.STRICT,  # STRICT, NORMAL, PERMISSIVE, AUDIT
    enable_audit_log=True,
    enable_rate_limit=True,
    allowed_tables={'users', 'orders'},  # Optional allowlist
    query_signing_secret='your-secret',  # HMAC signing
    compliance_mode=True  # Enhanced logging
)
```

## Response Format

When generating queries, provide:

1. **SQL Query** (formatted, commented)
2. **Parameters** (name, type, required/optional)
3. **Explanation** (what it does)
4. **Expected Result** structure
5. **Performance Notes** (indexes, optimization)
6. **Security Warnings** (if any)
7. **Implementation Example** (Python, Node.js, etc.)

## Example Response

```markdown
### SQL Query
```sql
-- Get active users with order counts
SELECT 
    u.user_id,
    u.username,
    u.email,
    COUNT(o.order_id) AS order_count
FROM 
    users u
LEFT JOIN 
    orders o ON u.user_id = o.user_id
WHERE 
    u.status = $1
    AND u.created_at >= $2
GROUP BY 
    u.user_id, u.username, u.email
HAVING 
    COUNT(o.order_id) >= $3
ORDER BY 
    order_count DESC
LIMIT $4;
```

### Parameters
| Param | Type | Required | Description |
|-------|------|----------|-------------|
| $1 | string | Yes | User status ('active') |
| $2 | date | Yes | Created after date |
| $3 | integer | No | Min orders (default: 5) |
| $4 | integer | No | Limit (default: 100) |

### Analysis
- **Complexity:** 35/100
- **Risk:** LOW
- **Performance:** 85/100
- **Security:** 95/100

### Recommendations
- Ensure index on `users.status`
- Ensure index on `orders.user_id`
- Consider pagination for large datasets
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run security tests
pytest tests/test_security.py -v

# Run with coverage
pytest --cov=sql_query_generator_v4 --cov-report=html
```

## Troubleshooting

### "Rate limit exceeded"
- Wait for window to reset
- Request trusted user status
- Increase limits in configuration

### "Table not allowed"
- Add table to `allowed_tables` set
- Or disable allowlist enforcement

### "Template not found"
- Check template ID spelling
- Use `templates.list_categories()` to browse

## Contributing

1. Fork repository
2. Create feature branch
3. Add tests for new features
4. Ensure all security tests pass
5. Submit PR

## License

MIT License - See LICENSE file.

## Support

- GitHub: https://github.com/cerbug45/sql-query-generator
- Issues: https://github.com/cerbug45/sql-query-generator/issues
