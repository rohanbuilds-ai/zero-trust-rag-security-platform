"""Authoritative SQLite database layer for Zero-Trust RAG (Phase 3)."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional, Dict, Any
import json
import datetime
import uuid
import hashlib

from zero_trust_rag.core.models import (
    DocumentRecord,
    ChunkRecord,
    DocumentStatus,
    ClassificationLevel,
    DocumentACLRecord,
    TrustStatus,
    SourceType,
    InspectionOutcome,
)
from zero_trust_rag.core.config import settings

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    clearance_level INTEGER NOT NULL DEFAULT 1,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE TABLE IF NOT EXISTS documents (
    document_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    title TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    classification_level INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    trust_score REAL NOT NULL DEFAULT 1.0,
    trust_status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
    source_type TEXT NOT NULL DEFAULT 'LOCAL_UPLOAD',
    inspection_status TEXT NOT NULL DEFAULT 'UNINSPECTED',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    is_public INTEGER NOT NULL DEFAULT 0,
    chunk_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE TABLE IF NOT EXISTS document_chunks (
    chunk_id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    token_count INTEGER NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    parent_hash TEXT NOT NULL DEFAULT '',
    classification_level INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    FOREIGN KEY (document_id) REFERENCES documents(document_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE TABLE IF NOT EXISTS document_acls (
    acl_id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL,
    grantee_type TEXT NOT NULL, -- 'USER' or 'ROLE'
    grantee_id TEXT NOT NULL,
    permission TEXT NOT NULL DEFAULT 'READ',
    FOREIGN KEY (document_id) REFERENCES documents(document_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS security_audit_events (
    event_id TEXT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    document_id TEXT,
    chunk_id TEXT,
    decision TEXT NOT NULL, -- 'PERMIT' or 'DENY'
    reason_code TEXT NOT NULL,
    query_hash TEXT,
    details_json TEXT
);
"""

class AuthoritativeDatabase:
    """Manages authoritative metadata, ACLs, document state, trust tracking, and audit logs."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or settings.sqlite_path
        if isinstance(self.db_path, Path):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._db_file = str(self.db_path)
        else:
            self._db_file = self.db_path

        self._init_db()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self._db_file, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)

            # Safe additive migrations for existing tables
            migrations = [
                ("documents", "trust_status", "TEXT NOT NULL DEFAULT 'PENDING_REVIEW'"),
                ("documents", "source_type", "TEXT NOT NULL DEFAULT 'LOCAL_UPLOAD'"),
                ("documents", "inspection_status", "TEXT NOT NULL DEFAULT 'UNINSPECTED'"),
                ("documents", "provenance_json", "TEXT NOT NULL DEFAULT '{}'"),
                ("document_chunks", "parent_hash", "TEXT NOT NULL DEFAULT ''"),
            ]
            for table, col, col_def in migrations:
                try:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def};")
                except sqlite3.OperationalError:
                    # Column already exists
                    pass

            # Seed default tenant if not exists
            conn.execute(
                "INSERT OR IGNORE INTO tenants (tenant_id, name) VALUES (?, ?)",
                ("default_tenant", "Default Enterprise Tenant")
            )
            # Seed secondary tenant for multi-tenant isolation tests
            conn.execute(
                "INSERT OR IGNORE INTO tenants (tenant_id, name) VALUES (?, ?)",
                ("tenant_isolated_beta", "Isolated Beta Tenant")
            )
            conn.commit()

    def insert_document(self, doc: DocumentRecord) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO documents (
                    document_id, tenant_id, owner_id, title, sha256_hash,
                    classification_level, status, trust_score, trust_status,
                    source_type, inspection_status, provenance_json,
                    is_public, chunk_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    doc.document_id,
                    doc.tenant_id,
                    doc.owner_id,
                    doc.title,
                    doc.sha256_hash,
                    int(doc.classification_level),
                    doc.status.value if hasattr(doc.status, "value") else str(doc.status),
                    doc.trust_score,
                    doc.trust_status.value if hasattr(doc.trust_status, "value") else str(doc.trust_status),
                    doc.source_type.value if hasattr(doc.source_type, "value") else str(doc.source_type),
                    doc.inspection_status.value if hasattr(doc.inspection_status, "value") else str(doc.inspection_status),
                    json.dumps(doc.provenance_json),
                    1 if doc.is_public else 0,
                    doc.chunk_count,
                    doc.created_at,
                    doc.updated_at,
                ),
            )
            conn.commit()

    def get_document(self, document_id: str) -> Optional[DocumentRecord]:
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM documents WHERE document_id = ?",
                (document_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            # Safe JSON parsing
            prov = {}
            if "provenance_json" in row.keys() and row["provenance_json"]:
                try:
                    prov = json.loads(row["provenance_json"])
                except Exception:
                    prov = {}

            return DocumentRecord(
                document_id=row["document_id"],
                tenant_id=row["tenant_id"],
                owner_id=row["owner_id"],
                title=row["title"],
                sha256_hash=row["sha256_hash"],
                classification_level=ClassificationLevel(row["classification_level"]),
                status=DocumentStatus(row["status"]),
                trust_score=row["trust_score"],
                trust_status=TrustStatus(row["trust_status"]) if "trust_status" in row.keys() else TrustStatus.PENDING_REVIEW,
                source_type=SourceType(row["source_type"]) if "source_type" in row.keys() else SourceType.LOCAL_UPLOAD,
                inspection_status=InspectionOutcome(row["inspection_status"]) if "inspection_status" in row.keys() else InspectionOutcome.UNINSPECTED,
                provenance_json=prov,
                is_public=bool(row["is_public"]),
                chunk_count=row["chunk_count"],
                created_at=str(row["created_at"]),
                updated_at=str(row["updated_at"]),
            )

    def insert_chunks(self, chunks: List[ChunkRecord]) -> None:
        if not chunks:
            return
        with self.get_connection() as conn:
            for chunk in chunks:
                conn.execute(
                    """
                    INSERT INTO document_chunks (
                        chunk_id, document_id, tenant_id, chunk_index,
                        token_count, content, content_hash, parent_hash,
                        classification_level, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        chunk.chunk_id,
                        chunk.document_id,
                        chunk.tenant_id,
                        chunk.chunk_index,
                        chunk.token_count,
                        chunk.content,
                        chunk.content_hash,
                        chunk.parent_hash,
                        int(chunk.classification_level),
                        chunk.status.value if hasattr(chunk.status, "value") else str(chunk.status),
                    ),
                )
            conn.commit()

    def get_chunk(self, chunk_id: str) -> Optional[ChunkRecord]:
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM document_chunks WHERE chunk_id = ?",
                (chunk_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return ChunkRecord(
                chunk_id=row["chunk_id"],
                document_id=row["document_id"],
                tenant_id=row["tenant_id"],
                chunk_index=row["chunk_index"],
                token_count=row["token_count"],
                content=row["content"],
                content_hash=row["content_hash"],
                parent_hash=row["parent_hash"] if "parent_hash" in row.keys() else "",
                classification_level=ClassificationLevel(row["classification_level"]),
                status=DocumentStatus(row["status"]),
            )

    def update_document_status(self, document_id: str, new_status: DocumentStatus) -> bool:
        status_str = new_status.value if hasattr(new_status, "value") else str(new_status)
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.execute(
                "UPDATE documents SET status = ?, updated_at = ? WHERE document_id = ?",
                (status_str, now_str, document_id),
            )
            if cursor.rowcount == 0:
                return False
            # Cascade status update to child chunks
            conn.execute(
                "UPDATE document_chunks SET status = ? WHERE document_id = ?",
                (status_str, document_id),
            )
            conn.commit()
            return True

    def update_document_trust_status(
        self,
        document_id: str,
        new_trust_status: TrustStatus,
        reason: Optional[str] = None
    ) -> bool:
        """
        Update trust state of a document (e.g. approve or quarantine) atomically.
        Synchronizes lifecycle status to ACTIVE when transitioning to TRUSTED,
        or to QUARANTINED when transitioning to QUARANTINED.
        Strictly refuses to modify or reactivate a REVOKED document.
        """
        trust_str = new_trust_status.value if hasattr(new_trust_status, "value") else str(new_trust_status)
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.get_connection() as conn:
            with conn:  # Atomic transaction
                cursor = conn.execute(
                    "SELECT status, trust_status FROM documents WHERE document_id = ?",
                    (document_id,)
                )
                row = cursor.fetchone()
                if not row:
                    return False

                current_status = row["status"]
                # Invariant: Never modify trust or reactivate a REVOKED document
                if current_status == DocumentStatus.REVOKED.value:
                    return False

                if new_trust_status == TrustStatus.QUARANTINED:
                    cursor = conn.execute(
                        """
                        UPDATE documents
                        SET trust_status = ?, status = ?, updated_at = ?
                        WHERE document_id = ?
                        """,
                        (trust_str, DocumentStatus.QUARANTINED.value, now_str, document_id)
                    )
                    conn.execute(
                        "UPDATE document_chunks SET status = ? WHERE document_id = ?",
                        (DocumentStatus.QUARANTINED.value, document_id)
                    )
                elif new_trust_status == TrustStatus.TRUSTED:
                    # Promoting to TRUSTED synchronizes document and chunks to ACTIVE
                    cursor = conn.execute(
                        """
                        UPDATE documents
                        SET trust_status = ?, status = ?, updated_at = ?
                        WHERE document_id = ?
                        """,
                        (trust_str, DocumentStatus.ACTIVE.value, now_str, document_id)
                    )
                    conn.execute(
                        "UPDATE document_chunks SET status = ? WHERE document_id = ?",
                        (DocumentStatus.ACTIVE.value, document_id)
                    )
                else:
                    cursor = conn.execute(
                        "UPDATE documents SET trust_status = ?, updated_at = ? WHERE document_id = ?",
                        (trust_str, now_str, document_id)
                    )

                return cursor.rowcount > 0

    def list_documents(self, tenant_id: Optional[str] = None) -> List[DocumentRecord]:
        with self.get_connection() as conn:
            if tenant_id:
                cursor = conn.execute(
                    "SELECT * FROM documents WHERE tenant_id = ? ORDER BY created_at DESC",
                    (tenant_id,)
                )
            else:
                cursor = conn.execute("SELECT * FROM documents ORDER BY created_at DESC")
            rows = cursor.fetchall()
            result = []
            for r in rows:
                prov = {}
                if "provenance_json" in r.keys() and r["provenance_json"]:
                    try:
                        prov = json.loads(r["provenance_json"])
                    except Exception:
                        prov = {}
                result.append(
                    DocumentRecord(
                        document_id=r["document_id"],
                        tenant_id=r["tenant_id"],
                        owner_id=r["owner_id"],
                        title=r["title"],
                        sha256_hash=r["sha256_hash"],
                        classification_level=ClassificationLevel(r["classification_level"]),
                        status=DocumentStatus(r["status"]),
                        trust_score=r["trust_score"],
                        trust_status=TrustStatus(r["trust_status"]) if "trust_status" in r.keys() else TrustStatus.PENDING_REVIEW,
                        source_type=SourceType(r["source_type"]) if "source_type" in r.keys() else SourceType.LOCAL_UPLOAD,
                        inspection_status=InspectionOutcome(r["inspection_status"]) if "inspection_status" in r.keys() else InspectionOutcome.UNINSPECTED,
                        provenance_json=prov,
                        is_public=bool(r["is_public"]),
                        chunk_count=r["chunk_count"],
                        created_at=str(r["created_at"]),
                        updated_at=str(r["updated_at"]),
                    )
                )
            return result

    # --- Document ACL Management ---

    def add_document_acl(
        self,
        document_id: str,
        grantee_type: str,
        grantee_id: str,
        permission: str = "READ"
    ) -> DocumentACLRecord:
        acl_id = f"acl_{uuid.uuid4().hex[:12]}"
        grantee_type = grantee_type.upper()
        permission = permission.upper()

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO document_acls (acl_id, document_id, grantee_type, grantee_id, permission)
                VALUES (?, ?, ?, ?, ?)
                """,
                (acl_id, document_id, grantee_type, grantee_id, permission)
            )
            conn.commit()

        return DocumentACLRecord(
            acl_id=acl_id,
            document_id=document_id,
            grantee_type=grantee_type,
            grantee_id=grantee_id,
            permission=permission
        )

    def get_document_acls(self, document_id: str) -> List[DocumentACLRecord]:
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM document_acls WHERE document_id = ?",
                (document_id,)
            )
            rows = cursor.fetchall()
            return [
                DocumentACLRecord(
                    acl_id=r["acl_id"],
                    document_id=r["document_id"],
                    grantee_type=r["grantee_type"],
                    grantee_id=r["grantee_id"],
                    permission=r["permission"]
                )
                for r in rows
            ]

    def check_document_acl(self, document_id: str, principal_id: str, role: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT 1 FROM document_acls
                WHERE document_id = ?
                  AND (
                    (grantee_type = 'USER' AND grantee_id = ?)
                    OR (grantee_type = 'ROLE' AND grantee_id = ?)
                  )
                LIMIT 1
                """,
                (document_id, principal_id, role)
            )
            return cursor.fetchone() is not None

    def delete_document_acl(self, acl_id: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM document_acls WHERE acl_id = ?",
                (acl_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    # --- Structured Security Audit Logging ---

    def log_audit_event(
        self,
        event_type: str,
        principal_id: str,
        tenant_id: str,
        decision: str,
        reason_code: str,
        document_id: Optional[str] = None,
        chunk_id: Optional[str] = None,
        query_text: Optional[str] = None,
        query_hash: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        event_id = f"aud_{uuid.uuid4().hex[:12]}"
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if query_text and not query_hash:
            query_hash = hashlib.sha256(query_text.encode("utf-8")).hexdigest()

        details_json = json.dumps(details or {})

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO security_audit_events (
                    event_id, timestamp, event_type, principal_id, tenant_id,
                    document_id, chunk_id, decision, reason_code, query_hash, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    now_str,
                    event_type,
                    principal_id,
                    tenant_id,
                    document_id,
                    chunk_id,
                    decision,
                    reason_code,
                    query_hash,
                    details_json,
                )
            )
            conn.commit()

        return event_id

    def get_audit_events(
        self,
        tenant_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            query = "SELECT * FROM security_audit_events"
            params = []
            conditions = []

            if tenant_id:
                conditions.append("tenant_id = ?")
                params.append(tenant_id)
            if event_type:
                conditions.append("event_type = ?")
                params.append(event_type)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
