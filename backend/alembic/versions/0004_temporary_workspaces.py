"""Anonymous expiring workspace isolation; legacy local assessments stay unowned."""

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "workspace_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("settings", sa.JSON(), nullable=False),
    )
    op.create_index("ix_workspace_sessions_expires_at", "workspace_sessions", ["expires_at"])
    op.execute("ALTER TABLE assessments ADD COLUMN owner_id VARCHAR(36) REFERENCES workspace_sessions(id)")
    op.add_column(
        "assessments", sa.Column("data_origin", sa.String(), nullable=False, server_default="COLLECTED")
    )
    op.create_index("ix_assessments_owner_id", "assessments", ["owner_id"])


def downgrade():
    op.drop_index("ix_assessments_owner_id", table_name="assessments")
    op.drop_column("assessments", "data_origin")
    op.drop_column("assessments", "owner_id")
    op.drop_table("workspace_sessions")
