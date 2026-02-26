# SQL Query Generator v4.0.0 - Enterprise Edition

[![Version](https://img.shields.io/badge/version-4.0.0-blue.svg)](https://github.com/cerbug45/sql-query-generator)
[![Python](https://img.shields.io/badge/python-3.7+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-military--grade-brightgreen.svg)](SECURITY.md)

**AI-Powered SQL Generation with Military-Grade Security**

---

## 🚀 What's New in v4.0.0

### Major Features

| Feature | Description | Status |
|---------|-------------|--------|
| **Query Templates** | 50+ pre-built secure templates | ✅ |
| **Query Versioning** | Git-like version control for queries | ✅ |
| **Schema Introspection** | Auto-discover and validate table structures | ✅ |
| **Query Signing** | HMAC-based integrity verification | ✅ |
| **Natural Language Parser** | Convert NL descriptions to SQL components | ✅ |
| **Multi-Dialect Transpiler** | Convert queries between database types | ✅ |
| **Query Analysis** | Comprehensive scoring (complexity, risk, performance, security) | ✅ |
| **Team Collaboration** | Real-time collaboration sessions | ✅ |
| **Compliance Mode** | SOX, GDPR, HIPAA audit logging | ✅ |
| **Adaptive Rate Limiting** | Smart rate limits with trusted users | ✅ |

### Security Enhancements

- ✅ Query tamper detection with HMAC signatures
- ✅ Role-based query permissions
- ✅ Query execution sandbox
- ✅ Automated security scanning
- ✅ Injection pattern detection (24+ patterns)
- ✅ Dangerous function blocking per database type
- ✅ Table allowlist enforcement
- ✅ Sensitive data redaction in logs

---

## 📦 Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/cerbug45/sql-query-generator.git
cd sql-query-generator

# No dependencies required for core functionality!
python sql_query_generator_v4.py
```

### With Optional Dependencies

```bash
# For database connections
pip install psycopg2-binary  # PostgreSQL
pip install mysql-connector-python  # MySQL
pip install pyodbc  # SQL Server

# For testing
pip install pytest pytest-cov
```

### Using as Module

```bash
cp sql_query_generator_v4.py /path/to/your/project/
```

```python
from sql_query_generator_v4 import SQLQueryGenerator, DatabaseType, SecurityLevel

generator = SQLQueryGenerator(
    DatabaseType.POSTGRESQL,
    security_level=SecurityLevel.STRICT,
    enable_audit_log=True
)
```

---

## 🎯 Usage Examples

### 1. Generate from Template (Recommended)

```python
from sql_query_generator_v4 import SQLQueryGenerator, DatabaseType

generator = SQLQueryGenerator(DatabaseType.POSTGRESQL)

# Use built-in template
query = generator.query_from_template(
    "crud_select_paginated",
    {
        "columns": "user_id, username, email",
        "table": "users",
        "where": "status = 'active'",
        "order_by": "created_at",
        "direction": "DESC",
        "limit": 50,
        "offset": 0
    },
    user_id="user_123"
)

print(query.sql)
```

**Output:**
```sql
SELECT
    user_id, username, email
FROM
    users
WHERE
    status = 'active'
ORDER BY
    created_at DESC
LIMIT 50
OFFSET 0;
```

### 2. Manual Query Generation

```python
query = generator.generate_select_query(
    tables=['users', 'orders'],
    columns=['u.user_id', 'u.username', 'COUNT(o.order_id) as total_orders'],
    joins=[{
        'type': 'LEFT',
        'table': 'orders',
        'on': 'u.user_id = o.user_id'
    }],
    where_conditions=['u.status = $1', 'u.created_at > $2'],
    group_by=['u.user_id', 'u.username'],
    order_by=['total_orders DESC'],
    limit=100,
    user_id='user_123'
)
```

### 3. Query Analysis

```python
analysis = generator.analyze_query(query)

print(f"Complexity: {analysis.complexity_score}/100")
print(f"Risk: {analysis.risk_score}/100 ({analysis.risk_level.value})")
print(f"Performance: {analysis.performance_score}/100")
print(f"Security: {analysis.security_score}/100")
print(f"Overall: {analysis.overall_score}/100")
print(f"Tags: {analysis.tags}")
print(f"Recommendations: {analysis.recommendations}")
```

### 4. Query Signing & Verification

```python
# Sign query for integrity
signature = generator.sign_query(query)

# Later, verify query hasn't been tampered
is_valid = generator.verify_query(query, signature)
print(f"Query integrity: {'VALID' if is_valid else 'TAMPERED'}")
```

### 5. Query Versioning

```python
# Create new version
version = generator.versioning.create_version(
    query_id="user_lookup",
    query=query,
    created_by="developer_1",
    changes="Initial version with pagination"
)

# Approve version
generator.versioning.approve_version(
    query_id="user_lookup",
    version="1.0.0",
    approved_by="tech_lead"
)

# Get version history
history = generator.versioning.get_version_history("user_lookup")

# Diff between versions
diff = generator.versioning.diff_versions("user_lookup", "1.0.0", "2.0.0")
```

### 6. Search Templates

```python
# Search by keyword
templates = generator.templates.search_templates("select")

# Search by category
templates = generator.templates.search_templates("", category="analytics")

# Search by tags
templates = generator.templates.search_templates("", tags=["security", "auth"])

for t in templates:
    print(f"{t.name}: {t.description}")
```

### 7. Multi-Dialect Transpilation

```python
# Generate for PostgreSQL
generator = SQLQueryGenerator(DatabaseType.POSTGRESQL)
query = generator.generate_select_query(
    tables=['users'],
    columns=['*'],
    limit=10
)

# Transpile to SQL Server
transpiled = generator.transpile_query(query, DatabaseType.MSSQL)
print(transpiled)
# SELECT TOP 10 * FROM users;
```

### 8. Schema Registration & Validation

```python
from sql_query_generator_v4 import TableSchema, ColumnSchema

# Register schema
schema = TableSchema(
    name="users",
    columns=[
        ColumnSchema(name="user_id", data_type="INTEGER", is_primary_key=True),
        ColumnSchema(name="username", data_type="VARCHAR", max_length=50),
        ColumnSchema(name="email", data_type="VARCHAR", max_length=254),
        ColumnSchema(name="status", data_type="VARCHAR", default="'active'")
    ]
)

generator.register_schema(schema)

# Now column validation is enforced
```

---

## 📚 Built-in Templates

### Categories

| Category | Templates | Description |
|----------|-----------|-------------|
| **Authentication** | 10 | Login, registration, password reset |
| **CRUD** | 15 | Safe SELECT, INSERT, UPDATE, DELETE |
| **Analytics** | 12 | Aggregations, time-series, cohorts |
| **Joins** | 8 | Various join patterns |
| **Reporting** | 10 | Top-N, rankings, summaries |

### Example Templates

```python
# List all templates
categories = generator.templates.list_categories()
print(categories)  # ['authentication', 'crud', 'analytics', 'joins', 'reporting']

# Get specific template
template = generator.templates.get_template("auth_login")
print(template.sql_template)
```

---

## 🔒 Security Features

### Input Validation

```python
from sql_query_generator_v4 import SQLInputValidator, SecurityLevel

# Validate identifier
table = SQLInputValidator.validate_identifier("users", security_level=SecurityLevel.STRICT)

# Validate string with injection check
value = SQLInputValidator.validate_string("user_input", check_injection=True)

# Validate email
email = SQLInputValidator.validate_email("user@example.com")

# Validate date
date = SQLInputValidator.validate_date("2024-01-01", format="YYYY-MM-DD")

# Validate UUID
uuid = SQLInputValidator.validate_uuid("550e8400-e29b-41d4-a716-446655440000")
```

### Injection Detection

```python
# Detects 24+ injection patterns including:
- UNION SELECT attacks
- DROP TABLE attempts
- xp_cmdshell execution
- Time-based blind injection (SLEEP, BENCHMARK)
- File operations (LOAD_FILE, INTO OUTFILE)
- Information schema enumeration
- Database-specific attacks (pg_sleep, dbms_pipe)

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

# All queries are logged with:
# - Timestamp, user_id, IP address
# - Query fingerprint
# - Execution time
# - Result count
# - Hostname, process ID (compliance mode)
```

### Rate Limiting

```python
# Adaptive rate limiting
generator.rate_limiter.add_trusted_user("admin_user")

# Check usage
stats = generator.rate_limiter.get_usage_stats("user_123")
print(stats)
# {'current_requests': 45, 'max_requests': 300, 'remaining': 255, ...}
```

---

## 📊 Query Analysis Scores

| Score Type | Range | Description |
|------------|-------|-------------|
| **Complexity** | 0-100 | Based on JOINs, subqueries, CTEs |
| **Risk** | 0-100 | Destructive operations, missing WHERE |
| **Performance** | 0-100 | SELECT *, missing LIMIT, many JOINs |
| **Security** | 0-100 | Parameterization, injection patterns |
| **Overall** | 0-100 | Weighted average |

### Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| **LOW** | 0-29 | Safe to execute |
| **MEDIUM** | 30-49 | Review recommended |
| **HIGH** | 50-79 | Requires approval |
| **CRITICAL** | 80-100 | Block execution |

---

## 🔧 Configuration

### Full Configuration Example

```python
generator = SQLQueryGenerator(
    database_type=DatabaseType.POSTGRESQL,
    security_level=SecurityLevel.STRICT,  # STRICT, NORMAL, PERMISSIVE, AUDIT
    enable_audit_log=True,
    enable_rate_limit=True,
    allowed_tables={'users', 'orders', 'products'},  # Table allowlist
    query_signing_secret='your-secret-key',  # HMAC signing
    compliance_mode=True  # Enhanced logging
)

# Configure rate limiter
generator.rate_limiter.max_requests = 100
generator.rate_limiter.window_seconds = 60
generator.rate_limiter.add_trusted_user("admin")
```

---

## 🧪 Testing

```bash
# Run tests
pytest tests/ -v --cov=sql_query_generator_v4

# Run with coverage report
pytest --cov-report=html

# Run security tests
pytest tests/test_security.py -v
```

---

## 📁 Project Structure

```
sql-query-generator/
├── sql_query_generator_v4.py    # Main module
├── README.md                     # This file
├── SKILL.md                      # ClawHub skill definition
├── SECURITY.md                   # Security documentation
├── examples/                     # Usage examples
│   ├── basic_usage.py
│   ├── templates.py
│   └── compliance.py
├── tests/                        # Test suite
│   ├── test_generator.py
│   ├── test_security.py
│   └── test_templates.py
└── query_versions/               # Version storage (auto-created)
```

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 📞 Support

- **GitHub Issues:** https://github.com/cerbug45/sql-query-generator/issues
- **Documentation:** https://github.com/cerbug45/sql-query-generator/wiki
- **Email:** contact@cerbug45.dev

---

## 🙏 Acknowledgments

- Security patterns from OWASP SQL Injection Prevention Cheat Sheet
- Query optimization techniques from database vendor documentation
- Compliance requirements from SOX, GDPR, HIPAA guidelines

---

**Made with ❤️ by [@cerbug45](https://github.com/cerbug45)**
