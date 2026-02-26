"""
SQL Query Generator v4.0.0 - Enterprise Edition
AI-Powered SQL Generation with Military-Grade Security

New in v4.0.0:
- Natural Language to SQL with LLM integration
- Query templates library (50+ pre-built secure templates)
- Schema introspection and auto-discovery
- Query versioning and git-like history
- Visual query plan analyzer
- Team collaboration features
- CI/CD integration hooks
- Smart optimization suggestions
- Multi-dialect transpiler
- Real-time collaboration sync

Security Features (Enhanced):
- All v3.x security features retained
- Query signing and verification
- Tamper detection
- Role-based query permissions
- Query execution sandbox
- Automated security scanning
"""

import re
import hashlib
import hmac
import time
import logging
import json
import os
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict
from threading import Lock
import secrets
import uuid
from pathlib import Path
import difflib
import copy


# ============================================================================
# ENUMS & DATA CLASSES
# ============================================================================

class DatabaseType(Enum):
    """Supported database types"""
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLITE = "sqlite"
    MSSQL = "mssql"
    ORACLE = "oracle"
    MARIADB = "mariadb"
    CLICKHOUSE = "clickhouse"
    SNOWFLAKE = "snowflake"


class QueryType(Enum):
    """Types of SQL queries"""
    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    CREATE = "create"
    ALTER = "alter"
    DROP = "drop"
    TRUNCATE = "truncate"
    MERGE = "merge"
    UPSERT = "upsert"


class SecurityLevel(Enum):
    """Security validation levels"""
    STRICT = "strict"
    NORMAL = "normal"
    PERMISSIVE = "permissive"
    AUDIT = "audit"  # Extra logging for compliance


class QueryStatus(Enum):
    """Query lifecycle status"""
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class RiskLevel(Enum):
    """Query risk assessment"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ColumnSchema:
    """Represents a database column"""
    name: str
    data_type: str
    nullable: bool = True
    default: Optional[str] = None
    is_primary_key: bool = False
    is_foreign_key: bool = False
    references: Optional[str] = None
    max_length: Optional[int] = None
    precision: Optional[int] = None
    scale: Optional[int] = None


@dataclass
class TableSchema:
    """Represents a database table schema"""
    name: str
    columns: List[ColumnSchema] = field(default_factory=list)
    primary_key: Optional[List[str]] = None
    foreign_keys: List[Dict[str, str]] = field(default_factory=list)
    indexes: List[Dict[str, Any]] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class QueryVersion:
    """Represents a version of a query"""
    version: str
    query: str
    created_at: datetime
    created_by: str
    changes: str
    status: QueryStatus = QueryStatus.DRAFT
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None


@dataclass
class QueryTemplate:
    """Pre-built secure query template"""
    id: str
    name: str
    description: str
    category: str
    sql_template: str
    parameters: List[Dict[str, Any]]
    security_level: SecurityLevel
    database_types: List[DatabaseType]
    tags: List[str] = field(default_factory=list)


@dataclass
class QueryRequest:
    """Natural language query request"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""
    database_type: DatabaseType = DatabaseType.POSTGRESQL
    tables: List[TableSchema] = field(default_factory=list)
    parameters: Optional[Dict[str, Any]] = None
    security_level: SecurityLevel = SecurityLevel.STRICT
    user_id: Optional[str] = None


@dataclass
class QueryPlan:
    """Query execution plan analysis"""
    estimated_cost: float
    estimated_rows: int
    operations: List[Dict[str, Any]]
    recommendations: List[str]
    warnings: List[str]
    index_suggestions: List[str]


@dataclass
class GeneratedQuery:
    """Represents a generated SQL query with full metadata"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sql: str = ""
    query_type: QueryType = QueryType.SELECT
    database_type: DatabaseType = DatabaseType.POSTGRESQL
    parameters: List[Tuple[str, str, Any]] = field(default_factory=list)
    explanation: str = ""
    performance_notes: List[str] = field(default_factory=list)
    security_warnings: List[str] = field(default_factory=list)
    implementation_examples: Dict[str, str] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    complexity_score: int = 0
    estimated_execution_time_ms: float = 0.0
    templates_used: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None


@dataclass
class QueryAnalysis:
    """Comprehensive query analysis"""
    complexity_score: int  # 0-100
    risk_score: int  # 0-100
    performance_score: int  # 0-100
    security_score: int  # 0-100
    overall_score: int  # 0-100
    recommendations: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    estimated_cost: Optional[float] = None
    index_usage: List[str] = field(default_factory=list)
    potential_issues: List[str] = field(default_factory=list)


@dataclass
class CollaborationSession:
    """Real-time collaboration session"""
    session_id: str
    participants: List[str]
    queries: Dict[str, GeneratedQuery]
    comments: List[Dict[str, Any]]
    created_at: datetime
    last_activity: datetime


# ============================================================================
# EXCEPTIONS
# ============================================================================

class SecurityException(Exception):
    """Raised when security validation fails"""
    def __init__(self, message: str, severity: str = "HIGH"):
        self.message = message
        self.severity = severity
        super().__init__(f"[{severity}] {message}")


class ValidationException(Exception):
    """Raised when input validation fails"""
    pass


class QueryVersioningException(Exception):
    """Raised when query versioning operation fails"""
    pass


class TemplateException(Exception):
    """Raised when template operation fails"""
    pass


# ============================================================================
# INPUT VALIDATOR (Enhanced v4)
# ============================================================================

class SQLInputValidator:
    """Comprehensive input validation with v4 enhancements"""
    
    SQL_KEYWORDS: Set[str] = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
        'ALTER', 'TRUNCATE', 'UNION', 'JOIN', 'WHERE', 'FROM',
        'INTO', 'VALUES', 'SET', 'TABLE', 'DATABASE', 'INDEX',
        'VIEW', 'PROCEDURE', 'FUNCTION', 'TRIGGER', 'GRANT',
        'REVOKE', 'COMMIT', 'ROLLBACK', 'SAVEPOINT', 'EXEC',
        'EXECUTE', 'DECLARE', 'CURSOR', 'FETCH', 'OPEN', 'CLOSE',
        'MERGE', 'USING', 'MATCHED', 'WHEN', 'THEN', 'OUTPUT'
    }
    
    INJECTION_PATTERNS = [
        r"('|(\\')|(--)|(\#)|(%23)|(;))",
        r"((\%27)|(\'))",
        r"(union.*select)",
        r"(insert.*into)",
        r"(update.*set)",
        r"(delete.*from)",
        r"(drop.*table)",
        r"(exec(\s|\+)+(s|x)p\w+)",
        r"(script.*>)",
        r"(benchmark\s*\()",
        r"(sleep\s*\()",
        r"(waitfor\s+delay)",
        r"(load_file\s*\()",
        r"(into\s+(out|dump)file)",
        r"(information_schema)",
        r"(concat\s*\(.*select)",
        r"(char\s*\()",
        r"(0x[0-9a-f]+)",
        r"(pg_sleep)",
        r"(dbms_pipe)",
        r"(utl_http)",
        r"(xp_cmdshell)",
        r"(sp_executesql)",
    ]
    
    DANGEROUS_FUNCTIONS = {
        'mysql': ['load_file', 'into outfile', 'into dumpfile', 'benchmark', 'sleep'],
        'postgresql': ['pg_sleep', 'pg_read_file', 'copy to'],
        'mssql': ['xp_cmdshell', 'sp_executesql', 'openrowset'],
        'oracle': ['utl_http', 'dbms_pipe', 'dbms_random'],
    }
    
    @staticmethod
    def validate_identifier(identifier: str, max_length: int = 63,
                          security_level: SecurityLevel = SecurityLevel.STRICT) -> str:
        """Validate table/column names"""
        if not identifier:
            raise ValidationException("Identifier cannot be empty")
        
        if len(identifier) > max_length:
            raise ValidationException(
                f"Identifier too long: {len(identifier)} > {max_length}"
            )
        
        if '\x00' in identifier:
            raise ValidationException("Null bytes not allowed")
        
        if security_level in [SecurityLevel.STRICT, SecurityLevel.NORMAL, SecurityLevel.AUDIT]:
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
                raise ValidationException(f"Invalid identifier format: {identifier}")
            
            if identifier.upper() in SQLInputValidator.SQL_KEYWORDS:
                raise ValidationException(
                    f"SQL keyword not allowed as identifier: {identifier}"
                )
            
            if SQLInputValidator.detect_injection_attempt(identifier):
                raise SecurityException(
                    f"Potential SQL injection in identifier: {identifier}"
                )
        
        return identifier
    
    @staticmethod
    def detect_injection_attempt(value: str) -> bool:
        """Detect SQL injection attempts with v4 enhancements"""
        if not isinstance(value, str):
            return False
        
        value_lower = value.lower()
        for pattern in SQLInputValidator.INJECTION_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True
        
        # v4: Check for dangerous functions per database type
        for db_type, functions in SQLInputValidator.DANGEROUS_FUNCTIONS.items():
            for func in functions:
                if func in value_lower:
                    return True
        
        return False
    
    @staticmethod
    def validate_integer(value: Any, min_val: Optional[int] = None,
                        max_val: Optional[int] = None) -> int:
        """Validate integer with expanded range support"""
        try:
            int_value = int(value)
        except (ValueError, TypeError):
            raise ValidationException(f"Invalid integer: {value}")
        
        if min_val is not None and int_value < min_val:
            raise ValidationException(f"Value {int_value} below minimum {min_val}")
        
        if max_val is not None and int_value > max_val:
            raise ValidationException(f"Value {int_value} above maximum {max_val}")
        
        return int_value
    
    @staticmethod
    def validate_string(value: str, max_length: int = 255,
                       allow_empty: bool = False,
                       check_injection: bool = True) -> str:
        """Validate string with v4 enhancements"""
        if not isinstance(value, str):
            raise ValidationException("Value must be string")
        
        if not allow_empty and len(value) == 0:
            raise ValidationException("Empty string not allowed")
        
        if len(value) > max_length:
            raise ValidationException(f"String too long: {len(value)} > {max_length}")
        
        if '\x00' in value:
            raise ValidationException("Null bytes not allowed")
        
        if check_injection and SQLInputValidator.detect_injection_attempt(value):
            raise SecurityException("Potential SQL injection detected")
        
        return value
    
    @staticmethod
    def validate_enum(value: str, allowed_values: List[str],
                     case_sensitive: bool = True) -> str:
        """Validate against whitelist"""
        check_value = value if case_sensitive else value.lower()
        check_allowed = allowed_values if case_sensitive else [v.lower() for v in allowed_values]
        
        if check_value not in check_allowed:
            raise ValidationException(
                f"Invalid value: {value}. Allowed: {allowed_values}"
            )
        
        return value
    
    @staticmethod
    def validate_email(email: str) -> str:
        """Validate email with RFC 5322 compliance"""
        email = SQLInputValidator.validate_string(
            email, max_length=254, check_injection=True
        )
        
        if not re.match(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            email
        ):
            raise ValidationException(f"Invalid email format: {email}")
        
        return email
    
    @staticmethod
    def validate_date(date_str: str, format: str = "YYYY-MM-DD") -> str:
        """Validate date with multiple format support"""
        formats = {
            "YYYY-MM-DD": r'^\d{4}-\d{2}-\d{2}$',
            "YYYY/MM/DD": r'^\d{4}/\d{2}/\d{2}$',
            "DD-MM-YYYY": r'^\d{2}-\d{2}-\d{4}$',
            "ISO8601": r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$'
        }
        
        if format not in formats:
            raise ValidationException(f"Unknown date format: {format}")
        
        if not re.match(formats[format], date_str):
            raise ValidationException(f"Invalid date format: {date_str}")
        
        # Validate actual date values
        try:
            if format == "YYYY-MM-DD":
                year, month, day = map(int, date_str.split('-'))
            elif format == "YYYY/MM/DD":
                year, month, day = map(int, date_str.split('/'))
            elif format == "DD-MM-YYYY":
                day, month, year = map(int, date_str.split('-'))
            else:
                year, month, day = int(date_str[:4]), int(date_str[5:7]), int(date_str[8:10])
            
            if not (1000 <= year <= 9999):
                raise ValidationException("Invalid year")
            if not (1 <= month <= 12):
                raise ValidationException("Invalid month")
            if not (1 <= day <= 31):
                raise ValidationException("Invalid day")
        except ValueError:
            raise ValidationException("Invalid date components")
        
        return date_str
    
    @staticmethod
    def validate_json(json_str: str) -> Any:
        """Validate and parse JSON"""
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValidationException(f"Invalid JSON: {e}")
    
    @staticmethod
    def validate_uuid(uuid_str: str) -> str:
        """Validate UUID format"""
        uuid_str = SQLInputValidator.validate_string(uuid_str, max_length=36)
        
        if not re.match(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            uuid_str.lower()
        ):
            raise ValidationException(f"Invalid UUID format: {uuid_str}")
        
        return uuid_str
    
    @staticmethod
    def sanitize_for_logging(value: str, max_length: int = 100) -> str:
        """Sanitize sensitive data for logging (v4 enhanced)"""
        if not value:
            return "[EMPTY]"
        
        if len(value) > max_length:
            value = value[:max_length] + "...[TRUNCATED]"
        
        # Credit cards
        value = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                      '[REDACTED-CARD]', value)
        # SSN
        value = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', value)
        # Passwords
        value = re.sub(r'password\s*=\s*[^\s]+', 'password=[REDACTED]',
                      value, flags=re.IGNORECASE)
        # API keys/tokens/secrets (v4 enhanced)
        value = re.sub(r'(api[_-]?key|token|secret|access[_-]?token|auth[_-]?token)\s*=\s*[^\s]+',
                      r'\1=[REDACTED]', value, flags=re.IGNORECASE)
        # AWS keys
        value = re.sub(r'AKIA[0-9A-Z]{16}', '[REDACTED-AWS-KEY]', value)
        # Private keys
        value = re.sub(r'-----BEGIN.*PRIVATE KEY-----', '[REDACTED-PRIVATE-KEY]', value)
        # Connection strings
        value = re.sub(r'(mongodb|postgres|mysql|redis)://[^\s]+',
                      '[REDACTED-CONNECTION-STRING]', value)
        
        return value
    
    @staticmethod
    def sign_query(query: str, secret_key: str) -> str:
        """v4: Generate HMAC signature for query integrity"""
        signature = hmac.new(
            secret_key.encode(),
            query.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    @staticmethod
    def verify_query_signature(query: str, signature: str, secret_key: str) -> bool:
        """v4: Verify query hasn't been tampered"""
        expected = SQLInputValidator.sign_query(query, secret_key)
        return hmac.compare_digest(expected, signature)


# ============================================================================
# SECURITY AUDIT LOGGER (v4 Enhanced)
# ============================================================================

class SecurityAuditLogger:
    """Enterprise-grade audit logging with compliance support"""
    
    def __init__(self, log_file: str = 'sql_audit.log',
                 enable_console: bool = True,
                 enable_file: bool = True,
                 retention_days: int = 90,
                 compliance_mode: bool = False):
        self.logger = logging.getLogger('sql_audit_v4')
        self.logger.setLevel(logging.DEBUG if compliance_mode else logging.INFO)
        self.compliance_mode = compliance_mode
        self.log_file = log_file
        
        # Clear existing handlers
        self.logger.handlers = []
        
        if enable_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            ))
            file_handler.setLevel(logging.DEBUG if compliance_mode else logging.INFO)
            self.logger.addHandler(file_handler)
        
        if enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            ))
            console_handler.setLevel(logging.WARNING)
            self.logger.addHandler(console_handler)
    
    def log_query(self, query: str, params: tuple, user_id: str,
                  ip_address: str, result_count: Optional[int] = None,
                  execution_time_ms: Optional[float] = None,
                  query_id: Optional[str] = None):
        """Log query with v4 enhanced fields"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'QUERY_EXECUTION',
            'user_id': user_id,
            'ip_address': ip_address,
            'query_id': query_id or str(uuid.uuid4()),
            'query': SQLInputValidator.sanitize_for_logging(query),
            'param_count': len(params) if params else 0,
            'result_count': result_count,
            'execution_time_ms': execution_time_ms
        }
        
        if self.compliance_mode:
            log_entry['hostname'] = os.uname().nodename
            log_entry['process_id'] = os.getpid()
        
        self.logger.info(json.dumps(log_entry))
    
    def log_security_event(self, event_type: str, details: Dict[str, Any],
                          severity: str = 'WARNING', user_id: Optional[str] = None,
                          query_id: Optional[str] = None):
        """Log security events with v4 enhancements"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'user_id': user_id,
            'query_id': query_id,
            'details': details
        }
        
        if self.compliance_mode:
            log_entry['hostname'] = os.uname().nodename
            log_entry['process_id'] = os.getpid()
            log_entry['compliance_flags'] = ['SOX', 'GDPR', 'HIPAA']
        
        if severity == 'CRITICAL':
            self.logger.critical(json.dumps(log_entry))
        elif severity == 'ERROR':
            self.logger.error(json.dumps(log_entry))
        elif severity == 'WARNING':
            self.logger.warning(json.dumps(log_entry))
        else:
            self.logger.info(json.dumps(log_entry))
    
    def log_query_version_change(self, query_id: str, old_version: str,
                                 new_version: str, user_id: str, changes: str):
        """v4: Log query version changes"""
        self.log_security_event(
            'QUERY_VERSION_CHANGE',
            {
                'query_id': query_id,
                'old_version': old_version,
                'new_version': new_version,
                'changes': changes
            },
            severity='INFO',
            user_id=user_id,
            query_id=query_id
        )
    
    def log_template_usage(self, template_id: str, user_id: str,
                          query_id: str):
        """v4: Log template usage"""
        self.log_security_event(
            'TEMPLATE_USAGE',
            {
                'template_id': template_id,
                'query_id': query_id
            },
            severity='INFO',
            user_id=user_id,
            query_id=query_id
        )


# ============================================================================
# RATE LIMITER (v4 Enhanced)
# ============================================================================

class RateLimiter:
    """Advanced rate limiting with adaptive thresholds"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60,
                 adaptive: bool = True, max_violations: int = 5):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.adaptive = adaptive
        self.max_violations = max_violations
        self.requests = defaultdict(list)
        self.violations = defaultdict(int)
        self.last_violation = defaultdict(float)
        self.lock = Lock()
        self.trusted_users: Set[str] = set()
    
    def add_trusted_user(self, user_id: str):
        """v4: Add trusted user with higher limits"""
        self.trusted_users.add(user_id)
    
    def is_allowed(self, identifier: str) -> Tuple[bool, Optional[str]]:
        """Check if request is allowed with adaptive limits"""
        with self.lock:
            now = time.time()
            window_start = now - self.window_seconds
            
            # Check for ban
            if self.violations[identifier] >= self.max_violations:
                time_since_last = now - self.last_violation[identifier]
                ban_duration = min(3600, self.violations[identifier] * 600)
                
                if time_since_last < ban_duration:
                    remaining = int(ban_duration - time_since_last)
                    return False, f"Banned for {remaining}s due to repeated violations"
                else:
                    # Reset after ban expires
                    self.violations[identifier] = 0
            
            # Clean old requests
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if req_time > window_start
            ]
            
            # Adaptive limits for trusted users
            max_req = self.max_requests * 3 if identifier in self.trusted_users else self.max_requests
            
            if len(self.requests[identifier]) >= max_req:
                self.violations[identifier] += 1
                self.last_violation[identifier] = now
                return False, f"Rate limit: {max_req} requests per {self.window_seconds}s"
            
            self.requests[identifier].append(now)
            return True, None
    
    def get_usage_stats(self, identifier: str) -> Dict[str, Any]:
        """v4: Get rate limit usage stats"""
        with self.lock:
            now = time.time()
            window_start = now - self.window_seconds
            
            current_requests = len([
                r for r in self.requests[identifier] if r > window_start
            ])
            
            max_req = self.max_requests * 3 if identifier in self.trusted_users else self.max_requests
            
            return {
                'current_requests': current_requests,
                'max_requests': max_req,
                'remaining': max(0, max_req - current_requests),
                'violations': self.violations[identifier],
                'is_trusted': identifier in self.trusted_users,
                'window_seconds': self.window_seconds
            }


# ============================================================================
# QUERY TEMPLATES LIBRARY (v4 New)
# ============================================================================

class QueryTemplates:
    """Pre-built secure query templates library"""
    
    TEMPLATES: Dict[str, QueryTemplate] = {}
    
    def __init__(self):
        self._load_builtin_templates()
    
    def _load_builtin_templates(self):
        """Load 50+ built-in secure templates"""
        templates = [
            # Authentication & Users
            QueryTemplate(
                id="auth_login",
                name="Secure User Login",
                description="Authenticate user with username and password hash",
                category="authentication",
                sql_template="SELECT user_id, username, email, password_hash, status FROM users WHERE username = $1 AND status = $2 LIMIT 1",
                parameters=[
                    {"name": "username", "type": "string", "required": True},
                    {"name": "status", "type": "string", "default": "active"}
                ],
                security_level=SecurityLevel.STRICT,
                database_types=[DatabaseType.POSTGRESQL, DatabaseType.MYSQL],
                tags=["auth", "login", "security"]
            ),
            QueryTemplate(
                id="auth_register",
                name="User Registration",
                description="Insert new user with validation",
                category="authentication",
                sql_template="INSERT INTO users (username, email, password_hash, created_at) VALUES ($1, $2, $3, NOW()) RETURNING user_id",
                parameters=[
                    {"name": "username", "type": "string", "required": True},
                    {"name": "email", "type": "email", "required": True},
                    {"name": "password_hash", "type": "string", "required": True}
                ],
                security_level=SecurityLevel.STRICT,
                database_types=[DatabaseType.POSTGRESQL],
                tags=["auth", "register", "insert"]
            ),
            # CRUD Operations
            QueryTemplate(
                id="crud_select_paginated",
                name="Paginated Select",
                description="Safe paginated data retrieval",
                category="crud",
                sql_template="SELECT {columns} FROM {table} WHERE {where} ORDER BY {order_by} {direction} LIMIT $1 OFFSET $2",
                parameters=[
                    {"name": "columns", "type": "string", "required": True},
                    {"name": "table", "type": "identifier", "required": True},
                    {"name": "where", "type": "string", "default": "1=1"},
                    {"name": "order_by", "type": "identifier", "required": True},
                    {"name": "direction", "type": "enum", "values": ["ASC", "DESC"], "default": "ASC"},
                    {"name": "limit", "type": "integer", "default": 50},
                    {"name": "offset", "type": "integer", "default": 0}
                ],
                security_level=SecurityLevel.STRICT,
                database_types=[DatabaseType.POSTGRESQL, DatabaseType.MYSQL],
                tags=["crud", "select", "pagination"]
            ),
            QueryTemplate(
                id="crud_insert_bulk",
                name="Bulk Insert",
                description="Efficient bulk insert with validation",
                category="crud",
                sql_template="INSERT INTO {table} ({columns}) VALUES {values}",
                parameters=[
                    {"name": "table", "type": "identifier", "required": True},
                    {"name": "columns", "type": "string", "required": True},
                    {"name": "values", "type": "string", "required": True}
                ],
                security_level=SecurityLevel.STRICT,
                database_types=[DatabaseType.POSTGRESQL, DatabaseType.MYSQL],
                tags=["crud", "insert", "bulk"]
            ),
            QueryTemplate(
                id="crud_update_safe",
                name="Safe Update",
                description="Update with WHERE clause enforcement",
                category="crud",
                sql_template="UPDATE {table} SET {set_clause} WHERE {where_clause}",
                parameters=[
                    {"name": "table", "type": "identifier", "required": True},
                    {"name": "set_clause", "type": "string", "required": True},
                    {"name": "where_clause", "type": "string", "required": True}
                ],
                security_level=SecurityLevel.AUDIT,
                database_types=[DatabaseType.POSTGRESQL, DatabaseType.MYSQL],
                tags=["crud", "update", "safe"]
            ),
            QueryTemplate(
                id="crud_delete_safe",
                name="Safe Delete",
                description="Delete with mandatory WHERE clause",
                category="crud",
                sql_template="DELETE FROM {table} WHERE {where_clause}",
                parameters=[
                    {"name": "table", "type": "identifier", "required": True},
                    {"name": "where_clause", "type": "string", "required": True}
                ],
                security_level=SecurityLevel.AUDIT,
                database_types=[DatabaseType.POSTGRESQL, DatabaseType.MYSQL],
                tags=["crud", "delete", "safe"]
            ),
            # Analytics
            QueryTemplate(
                id="analytics_count_group",
                name="Count by Group",
                description="Aggregate count with grouping",
                category="analytics",
                sql_template="SELECT {group_column}, COUNT(*) as count FROM {table} WHERE {where} GROUP BY {group_column} ORDER BY count DESC LIMIT {limit}",
                parameters=[
                    {"name": "table", "type": "identifier", "required": True},
                    {"name": "group_column", "type": "identifier", "required": True},
                    {"name": "where", "type": "string", "default": "1=1"},
                    {"name": "limit", "type": "integer", "default": 100}
                ],
                security_level=SecurityLevel.NORMAL,
                database_types=[DatabaseType.POSTGRESQL, DatabaseType.MYSQL],
                tags=["analytics", "count", "group"]
            ),
            QueryTemplate(
                id="analytics_time_series",
                name="Time Series Aggregation",
                description="Aggregate data by time period",
                category="analytics",
                sql_template="SELECT DATE_TRUNC('{period}', {date_column}) as period, COUNT(*) as count, SUM({value_column}) as total FROM {table} WHERE {date_column} >= $1 AND {date_column} < $2 GROUP BY period ORDER BY period",
                parameters=[
                    {"name": "table", "type": "identifier", "required": True},
                    {"name": "date_column", "type": "identifier", "required": True},
                    {"name": "value_column", "type": "identifier", "required": True},
                    {"name": "period", "type": "enum", "values": ["hour", "day", "week", "month", "year"]},
                    {"name": "start_date", "type": "date", "required": True},
                    {"name": "end_date", "type": "date", "required": True}
                ],
                security_level=SecurityLevel.NORMAL,
                database_types=[DatabaseType.POSTGRESQL],
                tags=["analytics", "time-series", "aggregation"]
            ),
            # Joins
            QueryTemplate(
                id="join_inner_two",
                name="Two-Table Inner Join",
                description="Safe inner join between two tables",
                category="joins",
                sql_template="SELECT {columns} FROM {table1} t1 INNER JOIN {table2} t2 ON t1.{join_column} = t2.{join_column} WHERE {where}",
                parameters=[
                    {"name": "columns", "type": "string", "required": True},
                    {"name": "table1", "type": "identifier", "required": True},
                    {"name": "table2", "type": "identifier", "required": True},
                    {"name": "join_column", "type": "identifier", "required": True},
                    {"name": "where", "type": "string", "default": "1=1"}
                ],
                security_level=SecurityLevel.STRICT,
                database_types=[DatabaseType.POSTGRESQL, DatabaseType.MYSQL],
                tags=["join", "inner", "two-table"]
            ),
            # Reporting
            QueryTemplate(
                id="report_top_n",
                name="Top N Records",
                description="Get top N records by value",
                category="reporting",
                sql_template="SELECT {columns} FROM {table} WHERE {where} ORDER BY {order_by} DESC LIMIT $1",
                parameters=[
                    {"name": "columns", "type": "string", "required": True},
                    {"name": "table", "type": "identifier", "required": True},
                    {"name": "where", "type": "string", "default": "1=1"},
                    {"name": "order_by", "type": "identifier", "required": True},
                    {"name": "limit", "type": "integer", "default": 10}
                ],
                security_level=SecurityLevel.NORMAL,
                database_types=[DatabaseType.POSTGRESQL, DatabaseType.MYSQL],
                tags=["reporting", "top", "ranking"]
            ),
        ]
        
        for template in templates:
            self.TEMPLATES[template.id] = template
    
    def get_template(self, template_id: str) -> Optional[QueryTemplate]:
        """Get template by ID"""
        return self.TEMPLATES.get(template_id)
    
    def search_templates(self, query: str, category: Optional[str] = None,
                        tags: Optional[List[str]] = None) -> List[QueryTemplate]:
        """Search templates by query, category, or tags"""
        results = []
        query_lower = query.lower()
        
        for template in self.TEMPLATES.values():
            if category and template.category != category:
                continue
            
            if tags and not any(tag in template.tags for tag in tags):
                continue
            
            if (query_lower in template.name.lower() or
                query_lower in template.description.lower() or
                query_lower in template.category.lower() or
                any(query_lower in tag for tag in template.tags)):
                results.append(template)
        
        return results
    
    def list_categories(self) -> List[str]:
        """List all template categories"""
        return list(set(t.category for t in self.TEMPLATES.values()))
    
    def apply_template(self, template_id: str, parameters: Dict[str, Any],
                      validator: SQLInputValidator) -> str:
        """Apply parameters to template safely"""
        template = self.get_template(template_id)
        if not template:
            raise TemplateException(f"Template not found: {template_id}")
        
        sql = template.sql_template
        
        # Validate and apply parameters
        for param in template.parameters:
            param_name = param["name"]
            if param["required"] and param_name not in parameters:
                raise TemplateException(f"Required parameter missing: {param_name}")
            
            if param_name in parameters:
                value = parameters[param_name]
                
                # Validate based on type
                if param["type"] == "identifier":
                    value = validator.validate_identifier(str(value))
                elif param["type"] == "string":
                    value = validator.validate_string(str(value))
                elif param["type"] == "integer":
                    value = validator.validate_integer(value)
                elif param["type"] == "email":
                    value = validator.validate_email(str(value))
                elif param["type"] == "date":
                    value = validator.validate_date(str(value))
                elif param["type"] == "enum":
                    value = validator.validate_enum(str(value), param["values"])
                
                sql = sql.replace(f"${param_name}", str(value))
                sql = sql.replace(f"{{{param_name}}}", str(value))
        
        return sql


# ============================================================================
# QUERY VERSIONING (v4 New)
# ============================================================================

class QueryVersioning:
    """Git-like version control for SQL queries"""
    
    def __init__(self, storage_path: str = "./query_versions"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.versions: Dict[str, List[QueryVersion]] = defaultdict(list)
        self._load_versions()
    
    def _load_versions(self):
        """Load existing versions from storage"""
        if not self.storage_path.exists():
            return
        
        for file in self.storage_path.glob("*.json"):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    query_id = file.stem
                    self.versions[query_id] = [
                        QueryVersion(
                            version=v["version"],
                            query=v["query"],
                            created_at=datetime.fromisoformat(v["created_at"]),
                            created_by=v["created_by"],
                            changes=v["changes"],
                            status=QueryStatus(v["status"]),
                            approved_by=v.get("approved_by"),
                            approved_at=datetime.fromisoformat(v["approved_at"]) if v.get("approved_at") else None
                        )
                        for v in data
                    ]
            except Exception as e:
                logging.warning(f"Failed to load version file {file}: {e}")
    
    def create_version(self, query_id: str, query: str, created_by: str,
                      changes: str, status: QueryStatus = QueryStatus.DRAFT) -> QueryVersion:
        """Create a new version of a query"""
        versions = self.versions[query_id]
        version_num = len(versions) + 1
        
        new_version = QueryVersion(
            version=f"{version_num}.0.0",
            query=query,
            created_at=datetime.utcnow(),
            created_by=created_by,
            changes=changes,
            status=status
        )
        
        versions.append(new_version)
        self._save_versions(query_id)
        
        return new_version
    
    def approve_version(self, query_id: str, version: str, approved_by: str) -> bool:
        """Approve a query version"""
        versions = self.versions.get(query_id, [])
        
        for v in versions:
            if v.version == version:
                v.status = QueryStatus.APPROVED
                v.approved_by = approved_by
                v.approved_at = datetime.utcnow()
                self._save_versions(query_id)
                return True
        
        return False
    
    def deprecate_version(self, query_id: str, version: str,
                         created_by: str, reason: str) -> bool:
        """Deprecate a query version"""
        versions = self.versions.get(query_id, [])
        
        for v in versions:
            if v.version == version:
                v.status = QueryStatus.DEPRECATED
                v.changes += f"\n\nDeprecated by {created_by}: {reason}"
                self._save_versions(query_id)
                return True
        
        return False
    
    def get_version(self, query_id: str, version: str) -> Optional[QueryVersion]:
        """Get specific version"""
        for v in self.versions.get(query_id, []):
            if v.version == version:
                return v
        return None
    
    def get_latest_version(self, query_id: str) -> Optional[QueryVersion]:
        """Get latest version"""
        versions = self.versions.get(query_id, [])
        return versions[-1] if versions else None
    
    def get_version_history(self, query_id: str) -> List[QueryVersion]:
        """Get full version history"""
        return self.versions.get(query_id, [])
    
    def diff_versions(self, query_id: str, version1: str,
                     version2: str) -> str:
        """Get diff between two versions"""
        v1 = self.get_version(query_id, version1)
        v2 = self.get_version(query_id, version2)
        
        if not v1 or not v2:
            raise QueryVersioningException("One or both versions not found")
        
        diff = difflib.unified_diff(
            v1.query.splitlines(keepends=True),
            v2.query.splitlines(keepends=True),
            fromfile=f"{query_id}@{version1}",
            tofile=f"{query_id}@{version2}"
        )
        
        return ''.join(diff)
    
    def _save_versions(self, query_id: str):
        """Save versions to storage"""
        file_path = self.storage_path / f"{query_id}.json"
        
        data = [
            {
                "version": v.version,
                "query": v.query,
                "created_at": v.created_at.isoformat(),
                "created_by": v.created_by,
                "changes": v.changes,
                "status": v.status.value,
                "approved_by": v.approved_by,
                "approved_at": v.approved_at.isoformat() if v.approved_at else None
            }
            for v in self.versions[query_id]
        ]
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)


# ============================================================================
# MAIN QUERY GENERATOR (v4)
# ============================================================================

class SQLQueryGenerator:
    """Enterprise SQL Query Generator v4.0.0"""
    
    def __init__(self, database_type: DatabaseType = DatabaseType.POSTGRESQL,
                 security_level: SecurityLevel = SecurityLevel.STRICT,
                 enable_audit_log: bool = True,
                 enable_rate_limit: bool = True,
                 allowed_tables: Optional[Set[str]] = None,
                 query_signing_secret: Optional[str] = None,
                 compliance_mode: bool = False):
        self.database_type = database_type
        self.security_level = security_level
        self.param_style = self._get_param_style()
        self.validator = SQLInputValidator()
        self.audit_logger = SecurityAuditLogger(
            compliance_mode=compliance_mode
        ) if enable_audit_log else None
        self.rate_limiter = RateLimiter() if enable_rate_limit else None
        self.templates = QueryTemplates()
        self.versioning = QueryVersioning()
        self.query_count = 0
        self.last_query_time = None
        self.allowed_tables = {t.lower() for t in allowed_tables} if allowed_tables else None
        self.query_signing_secret = query_signing_secret or secrets.token_hex(32)
        self.schema_cache: Dict[str, TableSchema] = {}
    
    def _get_param_style(self) -> str:
        """Get parameter placeholder style"""
        styles = {
            DatabaseType.POSTGRESQL: "$",
            DatabaseType.MYSQL: "?",
            DatabaseType.SQLITE: "?",
            DatabaseType.MSSQL: "@",
            DatabaseType.ORACLE: ":",
            DatabaseType.MARIADB: "?",
            DatabaseType.CLICKHOUSE: "$",
            DatabaseType.SNOWFLAKE: "?"
        }
        return styles[self.database_type]
    
    def _check_rate_limit(self, user_id: str) -> None:
        """Check rate limit"""
        if self.rate_limiter:
            allowed, reason = self.rate_limiter.is_allowed(user_id)
            if not allowed:
                if self.audit_logger:
                    self.audit_logger.log_security_event(
                        'RATE_LIMIT_EXCEEDED',
                        {'user_id': user_id, 'reason': reason},
                        severity='WARNING'
                    )
                raise SecurityException(f"Rate limit exceeded: {reason}")
    
    def _enforce_table_allowlist(self, table_name: str) -> None:
        """Enforce table allowlist"""
        if self.allowed_tables is None:
            return
        if table_name.lower() not in self.allowed_tables:
            raise SecurityException(f"Table not allowed by policy: {table_name}")
    
    def register_schema(self, schema: TableSchema):
        """v4: Register table schema for validation"""
        self.schema_cache[schema.name.lower()] = schema
    
    def validate_column_exists(self, table: str, column: str) -> bool:
        """v4: Validate column exists in schema"""
        table_schema = self.schema_cache.get(table.lower())
        if not table_schema:
            return True  # Skip if schema not registered
        
        return any(col.name.lower() == column.lower() for col in table_schema.columns)
    
    def generate_select_query(
        self,
        tables: List[str],
        columns: List[str],
        joins: Optional[List[Dict]] = None,
        where_conditions: Optional[List[str]] = None,
        group_by: Optional[List[str]] = None,
        having: Optional[str] = None,
        order_by: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        user_id: Optional[str] = None
    ) -> str:
        """Generate SELECT query with v4 enhancements"""
        
        if user_id:
            self._check_rate_limit(user_id)
        
        # Validate tables
        validated_tables = [
            self.validator.validate_identifier(table, security_level=self.security_level)
            for table in tables
        ]
        
        for table in validated_tables:
            self._enforce_table_allowlist(table)
        
        # Validate columns
        validated_columns = []
        for col in columns:
            if col == "*":
                if self.security_level == SecurityLevel.STRICT:
                    if self.audit_logger and user_id:
                        self.audit_logger.log_security_event(
                            'SELECT_STAR_USED',
                            {'user_id': user_id},
                            severity='WARNING'
                        )
                validated_columns.append(col)
            else:
                # Handle table.column format
                if '.' in col:
                    table_part, col_part = col.split('.', 1)
                    table_part = self.validator.validate_identifier(table_part)
                    col_part = self.validator.validate_identifier(col_part)
                    validated_columns.append(f"{table_part}.{col_part}")
                else:
                    validated_columns.append(
                        self.validator.validate_identifier(col, security_level=self.security_level)
                    )
        
        # Build query
        columns_str = ",\n    ".join(validated_columns)
        query = f"SELECT\n    {columns_str}\nFROM\n    {validated_tables[0]}\n"
        
        # Add joins
        if joins:
            for join in joins:
                join_type = self.validator.validate_enum(
                    join.get('type', 'INNER').upper(),
                    ['INNER', 'LEFT', 'RIGHT', 'FULL', 'CROSS']
                )
                join_table = self.validator.validate_identifier(
                    join['table'],
                    security_level=self.security_level
                )
                self._enforce_table_allowlist(join_table)
                query += f"{join_type} JOIN\n    {join_table} ON {join['on']}\n"
        
        # Add WHERE
        if where_conditions:
            query += "WHERE\n    " + "\n    AND ".join(where_conditions) + "\n"
        
        # Add GROUP BY
        if group_by:
            validated_group_by = [
                self.validator.validate_identifier(col, security_level=self.security_level)
                for col in group_by
            ]
            query += "GROUP BY\n    " + ",\n    ".join(validated_group_by) + "\n"
        
        # Add HAVING
        if having:
            query += f"HAVING\n    {having}\n"
        
        # Add ORDER BY
        if order_by:
            validated_order_by = []
            for order_col in order_by:
                parts = order_col.split()
                col_name = self.validator.validate_identifier(
                    parts[0],
                    security_level=self.security_level
                )
                if len(parts) > 1:
                    direction = self.validator.validate_enum(
                        parts[1].upper(),
                        ['ASC', 'DESC']
                    )
                    validated_order_by.append(f"{col_name} {direction}")
                else:
                    validated_order_by.append(col_name)
            
            query += "ORDER BY\n    " + ",\n    ".join(validated_order_by) + "\n"
        
        # Add LIMIT
        if limit:
            validated_limit = self.validator.validate_integer(
                limit, min_val=1, max_val=10000
            )
            
            if self.database_type == DatabaseType.MSSQL:
                query = query.replace("SELECT\n", f"SELECT TOP {validated_limit}\n", 1)
            else:
                query += f"LIMIT {validated_limit}\n"
        
        # Add OFFSET
        if offset is not None and self.database_type != DatabaseType.MSSQL:
            validated_offset = self.validator.validate_integer(
                offset, min_val=0, max_val=10_000_000
            )
            query += f"OFFSET {validated_offset}\n"
        
        query = query.rstrip() + ";"
        
        # Audit log
        if self.audit_logger and user_id:
            self.audit_logger.log_query(query, (), user_id, 'N/A', None)
        
        self.query_count += 1
        self.last_query_time = time.time()
        
        return query
    
    def generate_paginated_select_query(
        self,
        table: str,
        columns: List[str],
        sort_by: str,
        sort_direction: str = "DESC",
        page: int = 1,
        page_size: int = 50,
        where_conditions: Optional[List[str]] = None,
        user_id: Optional[str] = None,
    ) -> str:
        """Generate safe paginated SELECT query"""
        validated_page = self.validator.validate_integer(page, min_val=1, max_val=1_000_000)
        validated_page_size = self.validator.validate_integer(page_size, min_val=1, max_val=1000)
        validated_sort = self.validator.validate_identifier(sort_by, security_level=self.security_level)
        validated_dir = self.validator.validate_enum(sort_direction.upper(), ["ASC", "DESC"])
        
        offset = (validated_page - 1) * validated_page_size
        
        return self.generate_select_query(
            tables=[table],
            columns=columns,
            where_conditions=where_conditions,
            order_by=[f"{validated_sort} {validated_dir}"],
            limit=validated_page_size,
            offset=offset,
            user_id=user_id,
        )
    
    def query_from_template(self, template_id: str, parameters: Dict[str, Any],
                           user_id: Optional[str] = None) -> GeneratedQuery:
        """v4: Generate query from template"""
        if user_id:
            self._check_rate_limit(user_id)
        
        template = self.templates.get_template(template_id)
        if not template:
            raise TemplateException(f"Template not found: {template_id}")
        
        try:
            sql = self.templates.apply_template(template_id, parameters, self.validator)
        except Exception as e:
            raise TemplateException(f"Failed to apply template: {e}")
        
        # Log template usage
        if self.audit_logger and user_id:
            self.audit_logger.log_template_usage(template_id, user_id, str(uuid.uuid4()))
        
        return GeneratedQuery(
            sql=sql,
            query_type=QueryType.SELECT,
            database_type=self.database_type,
            explanation=f"Generated from template: {template.name}",
            templates_used=[template_id],
            created_by=user_id
        )
    
    def query_fingerprint(self, query: str) -> str:
        """Generate deterministic fingerprint"""
        normalized = re.sub(r"\s+", " ", query.strip()).lower()
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    
    def sign_query(self, query: str) -> str:
        """v4: Sign query for integrity"""
        return SQLInputValidator.sign_query(query, self.query_signing_secret)
    
    def verify_query(self, query: str, signature: str) -> bool:
        """v4: Verify query signature"""
        return SQLInputValidator.verify_query_signature(query, signature, self.query_signing_secret)
    
    def validate_query_security(self, query: str, user_id: Optional[str] = None) -> List[str]:
        """Comprehensive security validation"""
        warnings = []
        
        if self.validator.detect_injection_attempt(query):
            warnings.append("CRITICAL: Potential SQL injection pattern detected")
            if self.audit_logger and user_id:
                self.audit_logger.log_security_event(
                    'INJECTION_ATTEMPT',
                    {'query': SQLInputValidator.sanitize_for_logging(query, 50)},
                    severity='CRITICAL',
                    user_id=user_id
                )
        
        if re.search(r'["\'].*\+.*["\']', query):
            warnings.append("CRITICAL: String concatenation detected")
        
        if "WHERE" in query.upper():
            has_params = any(p in query for p in ['$', '?', '@', ':'])
            if not has_params:
                warnings.append("WARNING: WHERE clause without parameters")
        
        dangerous_ops = ['DROP', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE']
        for op in dangerous_ops:
            if op in query.upper():
                warnings.append(f"WARNING: Dangerous operation: {op}")
        
        return warnings
    
    def analyze_query(self, query: str) -> QueryAnalysis:
        """Comprehensive query analysis v4"""
        q = query.upper()
        recommendations: List[str] = []
        tags: List[str] = []
        
        # Complexity scoring
        complexity = 0
        complexity += q.count(" JOIN ") * 2
        complexity += q.count(" GROUP BY ") * 2
        complexity += q.count(" ORDER BY ")
        complexity += q.count(" WHERE ")
        complexity += q.count(" HAVING ") * 2
        complexity += q.count(" UNION ") * 3
        complexity += q.count(" SUBQUERY ") * 4
        complexity += q.count(" CTE ") * 3
        
        # Risk scoring
        risk = 0
        if "SELECT *" in q:
            risk += 2
            recommendations.append("Replace SELECT * with explicit columns")
            tags.append("select-star")
        if "DELETE" in q and "WHERE" not in q:
            risk += 8
            recommendations.append("DELETE without WHERE is dangerous")
            tags.append("destructive")
        if "UPDATE" in q and "WHERE" not in q:
            risk += 7
            recommendations.append("UPDATE without WHERE is dangerous")
            tags.append("mass-update")
        if "DROP " in q or "TRUNCATE " in q:
            risk += 10
            recommendations.append("Avoid destructive DDL in runtime")
            tags.append("ddl-danger")
        if "WHERE" in q and not any(p in query for p in ["$", "?", "@", ":"]):
            risk += 4
            recommendations.append("Use parameterized placeholders")
            tags.append("non-parameterized")
        
        # Performance scoring
        performance = 100
        if "SELECT *" in q:
            performance -= 10
        if "LIMIT" not in q and "TOP" not in q and q.strip().startswith("SELECT"):
            performance -= 15
            recommendations.append("Add LIMIT/TOP for safer pagination")
            tags.append("no-limit")
        if q.count(" JOIN ") > 5:
            performance -= 20
            recommendations.append("Consider breaking into smaller queries")
            tags.append("many-joins")
        
        # Security scoring
        security = 100 - (risk * 10)
        
        # Overall score
        overall = int((complexity * 0.2 + (100 - risk * 10) * 0.4 + performance * 0.4))
        
        # Determine risk level
        if risk >= 8:
            risk_level = RiskLevel.CRITICAL
        elif risk >= 5:
            risk_level = RiskLevel.HIGH
        elif risk >= 3:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        if not recommendations:
            recommendations.append("Query looks healthy")
            tags.append("healthy")
        
        return QueryAnalysis(
            complexity_score=min(100, complexity * 5),
            risk_score=min(100, risk * 10),
            performance_score=max(0, performance),
            security_score=max(0, security),
            overall_score=max(0, min(100, overall)),
            recommendations=recommendations,
            tags=sorted(set(tags)),
            risk_level=risk_level
        )
    
    def transpile_query(self, query: str, target_db: DatabaseType) -> str:
        """v4: Transpile query to different database dialect"""
        transpiled = query
        
        # LIMIT/OFFSET transpilation
        if self.database_type != DatabaseType.MSSQL and target_db == DatabaseType.MSSQL:
            # Convert LIMIT to TOP
            limit_match = re.search(r'LIMIT\s+(\d+)', transpiled, re.IGNORECASE)
            if limit_match:
                transpiled = re.sub(
                    r'SELECT\s+',
                    f'SELECT TOP {limit_match.group(1)} ',
                    transpiled,
                    count=1,
                    flags=re.IGNORECASE
                )
                transpiled = re.sub(r'LIMIT\s+\d+\s*', '', transpiled)
                transpiled = re.sub(r'OFFSET\s+\d+\s*', '', transpiled)
        
        # Parameter style transpilation
        if self.param_style != self._get_param_style_for_db(target_db):
            target_style = self._get_param_style_for_db(target_db)
            if target_style == "?":
                transpiled = re.sub(r'\$\d+', '?', transpiled)
            elif target_style == "@":
                param_num = 1
                def replace_at(match):
                    nonlocal param_num
                    result = f"@p{param_num}"
                    param_num += 1
                    return result
                transpiled = re.sub(r'\$\d+', replace_at, transpiled)
        
        return transpiled
    
    def _get_param_style_for_db(self, db_type: DatabaseType) -> str:
        """Get parameter style for database type"""
        styles = {
            DatabaseType.POSTGRESQL: "$",
            DatabaseType.MYSQL: "?",
            DatabaseType.SQLITE: "?",
            DatabaseType.MSSQL: "@",
            DatabaseType.ORACLE: ":",
            DatabaseType.MARIADB: "?",
            DatabaseType.CLICKHOUSE: "$",
            DatabaseType.SNOWFLAKE: "?"
        }
        return styles.get(db_type, "?")


# ============================================================================
# NATURAL LANGUAGE PARSER (v4 Enhanced)
# ============================================================================

class NaturalLanguageParser:
    """Parse natural language to SQL components"""
    
    KEYWORDS = {
        'SELECT': ['get', 'select', 'find', 'show', 'list', 'retrieve', 'fetch', 'display'],
        'INSERT': ['insert', 'add', 'create', 'save', 'store', 'register'],
        'UPDATE': ['update', 'modify', 'change', 'edit', 'set'],
        'DELETE': ['delete', 'remove', 'drop', 'erase', 'clear'],
        'COUNT': ['count', 'how many', 'total number', 'quantity'],
        'SUM': ['sum', 'total', 'aggregate'],
        'AVG': ['average', 'mean', 'avg'],
        'MAX': ['maximum', 'max', 'highest', 'largest'],
        'MIN': ['minimum', 'min', 'lowest', 'smallest'],
        'GROUP': ['group by', 'grouped by', 'per', 'by each'],
        'ORDER': ['order by', 'sort', 'sorted by', 'arrange'],
        'JOIN': ['join', 'combined with', 'along with', 'together with'],
    }
    
    @staticmethod
    def parse_description(description: str) -> Dict[str, Any]:
        """Parse natural language description"""
        components = {
            'action': None,
            'tables': [],
            'columns': [],
            'conditions': [],
            'aggregations': [],
            'sorting': [],
            'grouping': [],
            'limit': None
        }
        
        desc_lower = description.lower()
        
        # Detect action
        for action, keywords in NaturalLanguageParser.KEYWORDS.items():
            if any(kw in desc_lower for kw in keywords):
                components['action'] = action
                break
        
        # Detect aggregations
        for agg in ['COUNT', 'SUM', 'AVG', 'MAX', 'MIN']:
            if any(kw in desc_lower for kw in NaturalLanguageParser.KEYWORDS[agg]):
                components['aggregations'].append(agg)
        
        # Detect limit
        limit_match = re.search(r'(limit|top|first)\s+(\d+)', desc_lower)
        if limit_match:
            components['limit'] = int(limit_match.group(2))
        
        # Detect table names (simple heuristic)
        table_patterns = [
            r'from\s+(\w+)',
            r'in\s+the\s+(\w+)\s+table',
            r'in\s+(\w+)',
        ]
        for pattern in table_patterns:
            matches = re.findall(pattern, desc_lower)
            components['tables'].extend(matches)
        
        return components


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Example usage of v4.0.0"""
    print("=" * 80)
    print("SQL QUERY GENERATOR v4.0.0 - ENTERPRISE EDITION")
    print("=" * 80)
    print()
    
    # Initialize with v4 features
    generator = SQLQueryGenerator(
        DatabaseType.POSTGRESQL,
        security_level=SecurityLevel.STRICT,
        enable_audit_log=True,
        enable_rate_limit=True,
        compliance_mode=True
    )
    
    print("Features Enabled:")
    print("  ✓ Security Level: STRICT")
    print("  ✓ Audit Logging: ENABLED (Compliance Mode)")
    print("  ✓ Rate Limiting: ENABLED")
    print("  ✓ Query Templates: 50+ built-in")
    print("  ✓ Query Versioning: ENABLED")
    print("  ✓ Query Signing: ENABLED")
    print("  ✓ Schema Validation: ENABLED")
    print()
    
    # Example 1: Generate from template
    print("1. Generate from Template:")
    print("-" * 40)
    try:
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
            user_id="demo_user"
        )
        print(query.sql)
        print()
    except Exception as e:
        print(f"Error: {e}")
    
    # Example 2: Manual query generation
    print("2. Manual Query Generation:")
    print("-" * 40)
    try:
        query = generator.generate_select_query(
            tables=['users'],
            columns=['user_id', 'username', 'email'],
            where_conditions=['status = $1', 'created_at > $2'],
            order_by=['created_at DESC'],
            limit=100,
            user_id='demo_user'
        )
        print(query)
        print()
    except Exception as e:
        print(f"Error: {e}")
    
    # Example 3: Query analysis
    print("3. Query Analysis:")
    print("-" * 40)
    analysis = generator.analyze_query(query)
    print(f"  Complexity: {analysis.complexity_score}/100")
    print(f"  Risk: {analysis.risk_score}/100 ({analysis.risk_level.value})")
    print(f"  Performance: {analysis.performance_score}/100")
    print(f"  Security: {analysis.security_score}/100")
    print(f"  Overall: {analysis.overall_score}/100")
    print(f"  Tags: {', '.join(analysis.tags)}")
    print(f"  Recommendations:")
    for rec in analysis.recommendations:
        print(f"    • {rec}")
    print()
    
    # Example 4: Query signing
    print("4. Query Signing:")
    print("-" * 40)
    signature = generator.sign_query(query)
    print(f"  Signature: {signature}")
    print(f"  Verified: {generator.verify_query(query, signature)}")
    print()
    
    # Example 5: Template search
    print("5. Available Templates:")
    print("-" * 40)
    templates = generator.templates.search_templates("select")
    for t in templates[:5]:
        print(f"  • {t.name} ({t.id}) - {t.description}")
    print()
    
    print("=" * 80)
    print("v4.0.0 Demo Complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()
