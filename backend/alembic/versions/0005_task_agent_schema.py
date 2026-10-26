"""Add task-centric agent persistence.

Revision ID: 0005_task_agent_schema
Revises: 0004_add_exploitation_schema
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0005_task_agent_schema"
down_revision: Union[str, None] = "0004_add_exploitation_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _timestamps() -> list:
    return [
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "agent_tasks",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("user_goal", sa.Text(), nullable=False),
        sa.Column("target", sa.String(length=4096), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("allowed_hosts", sa.JSON(), nullable=False),
        sa.Column("allowed_ports", sa.JSON(), nullable=False),
        sa.Column("authorized_lab_scope", sa.Boolean(), nullable=False),
        sa.Column("input_files", sa.JSON(), nullable=False),
        sa.Column("expected_outputs", sa.JSON(), nullable=False),
        sa.Column("permitted_actions", sa.JSON(), nullable=False),
        sa.Column("maximum_steps", sa.Integer(), nullable=False),
        sa.Column("maximum_runtime", sa.Integer(), nullable=False),
        sa.Column("maximum_repair_attempts", sa.Integer(), nullable=False),
        sa.Column("network_policy", sa.String(length=32), nullable=False),
        sa.Column("approval_required", sa.Boolean(), nullable=False),
        sa.Column("current_status", sa.String(length=64), nullable=False),
        sa.Column("current_step", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("stop_reason", sa.String(length=2048), nullable=True),
        sa.Column("model_name", sa.String(length=256), nullable=True),
        sa.Column("scope_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("report_json_path", sa.String(length=2048), nullable=True),
        sa.Column("report_md_path", sa.String(length=2048), nullable=True),
        *_timestamps(),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_tasks"),
    )
    op.create_index("ix_agent_tasks_current_status", "agent_tasks", ["current_status"])

    op.create_table(
        "agent_task_steps",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(length=64), nullable=False),
        sa.Column("action_id", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.String(length=2048), nullable=True),
        sa.Column("arguments", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("target", sa.String(length=4096), nullable=True),
        sa.Column("expected_result", sa.String(length=2048), nullable=True),
        sa.Column("risk_level", sa.String(length=32), nullable=True),
        sa.Column("requires_approval", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("policy_allowed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("policy_reason", sa.String(length=2048), nullable=True),
        sa.Column("observation", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("verification", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("retrieved_skills", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("model_name", sa.String(length=256), nullable=True),
        sa.Column("request_id", sa.String(length=256), nullable=True),
        sa.Column("response_id", sa.String(length=256), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["task_id"], ["agent_tasks.id"], ondelete="CASCADE",
            name="fk_agent_task_steps_task_id_agent_tasks",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_task_steps"),
        sa.UniqueConstraint(
            "task_id", "step_number", name="uq_agent_task_steps_task_order"
        ),
    )
    op.create_index("ix_agent_task_steps_task_id", "agent_task_steps", ["task_id"])

    op.create_table(
        "agent_code_versions",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("step_id", sa.String(length=128), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("code", sa.Text(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("error", sa.String(length=2048), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["step_id"], ["agent_task_steps.id"], ondelete="SET NULL",
            name="fk_agent_code_versions_step_id_agent_task_steps",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["agent_tasks.id"], ondelete="CASCADE",
            name="fk_agent_code_versions_task_id_agent_tasks",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_code_versions"),
        sa.UniqueConstraint(
            "task_id", "version", name="uq_agent_code_versions_task_version"
        ),
    )
    op.create_index("ix_agent_code_versions_task_id", "agent_code_versions", ["task_id"])
    op.create_index("ix_agent_code_versions_step_id", "agent_code_versions", ["step_id"])

    op.create_table(
        "agent_artifacts",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("step_id", sa.String(length=128), nullable=True),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["step_id"], ["agent_task_steps.id"], ondelete="SET NULL",
            name="fk_agent_artifacts_step_id_agent_task_steps",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["agent_tasks.id"], ondelete="CASCADE",
            name="fk_agent_artifacts_task_id_agent_tasks",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_artifacts"),
    )
    op.create_index("ix_agent_artifacts_task_id", "agent_artifacts", ["task_id"])
    op.create_index("ix_agent_artifacts_step_id", "agent_artifacts", ["step_id"])

    op.create_table(
        "agent_evidence",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("step_id", sa.String(length=128), nullable=True),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.String(length=2048), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("artifact_path", sa.String(length=2048), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["step_id"], ["agent_task_steps.id"], ondelete="SET NULL",
            name="fk_agent_evidence_step_id_agent_task_steps",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["agent_tasks.id"], ondelete="CASCADE",
            name="fk_agent_evidence_task_id_agent_tasks",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_evidence"),
    )
    op.create_index("ix_agent_evidence_task_id", "agent_evidence", ["task_id"])
    op.create_index("ix_agent_evidence_step_id", "agent_evidence", ["step_id"])

    op.create_table(
        "agent_reports",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("report_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("report_md", sa.Text(), nullable=False),
        sa.Column("json_path", sa.String(length=2048), nullable=True),
        sa.Column("md_path", sa.String(length=2048), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["agent_tasks.id"], ondelete="CASCADE",
            name="fk_agent_reports_task_id_agent_tasks",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_reports"),
    )
    op.create_index("ix_agent_reports_task_id", "agent_reports", ["task_id"])

    op.create_table(
        "agent_approvals",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("step_id", sa.String(length=128), nullable=True),
        sa.Column("action_id", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.String(length=2048), nullable=True),
        sa.Column("risk_level", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="pending"),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by", sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(
            ["step_id"], ["agent_task_steps.id"], ondelete="SET NULL",
            name="fk_agent_approvals_step_id_agent_task_steps",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["agent_tasks.id"], ondelete="CASCADE",
            name="fk_agent_approvals_task_id_agent_tasks",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_approvals"),
    )
    op.create_index("ix_agent_approvals_task_id", "agent_approvals", ["task_id"])
    op.create_index("ix_agent_approvals_step_id", "agent_approvals", ["step_id"])

    op.create_table(
        "agent_target_sessions",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("session_key", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("target_host", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="open"),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["agent_tasks.id"], ondelete="CASCADE",
            name="fk_agent_target_sessions_task_id_agent_tasks",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_target_sessions"),
        sa.UniqueConstraint(
            "task_id", "session_key", name="uq_agent_target_sessions_task_key"
        ),
    )
    op.create_index("ix_agent_target_sessions_task_id", "agent_target_sessions", ["task_id"])

    op.create_table(
        "agent_audit_events",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("action_id", sa.String(length=128), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["agent_tasks.id"], ondelete="SET NULL",
            name="fk_agent_audit_events_task_id_agent_tasks",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_audit_events"),
    )
    op.create_index("ix_agent_audit_events_task_id", "agent_audit_events", ["task_id"])
    op.create_index("ix_agent_audit_events_event_type", "agent_audit_events", ["event_type"])


def downgrade() -> None:
    op.drop_index("ix_agent_audit_events_event_type", table_name="agent_audit_events")
    op.drop_index("ix_agent_audit_events_task_id", table_name="agent_audit_events")
    op.drop_table("agent_audit_events")
    op.drop_index("ix_agent_target_sessions_task_id", table_name="agent_target_sessions")
    op.drop_table("agent_target_sessions")
    op.drop_index("ix_agent_approvals_step_id", table_name="agent_approvals")
    op.drop_index("ix_agent_approvals_task_id", table_name="agent_approvals")
    op.drop_table("agent_approvals")
    op.drop_index("ix_agent_reports_task_id", table_name="agent_reports")
    op.drop_table("agent_reports")
    op.drop_index("ix_agent_evidence_step_id", table_name="agent_evidence")
    op.drop_index("ix_agent_evidence_task_id", table_name="agent_evidence")
    op.drop_table("agent_evidence")
    op.drop_index("ix_agent_artifacts_step_id", table_name="agent_artifacts")
    op.drop_index("ix_agent_artifacts_task_id", table_name="agent_artifacts")
    op.drop_table("agent_artifacts")
    op.drop_index("ix_agent_code_versions_step_id", table_name="agent_code_versions")
    op.drop_index("ix_agent_code_versions_task_id", table_name="agent_code_versions")
    op.drop_table("agent_code_versions")
    op.drop_index("ix_agent_task_steps_task_id", table_name="agent_task_steps")
    op.drop_table("agent_task_steps")
    op.drop_index("ix_agent_tasks_current_status", table_name="agent_tasks")
    op.drop_table("agent_tasks")
