"""Enforce same-assessment derived-evidence provenance."""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "evidence_links",
        sa.Column("parent_id", sa.String(), nullable=False),
        sa.Column("child_id", sa.String(), nullable=False),
        sa.Column("assessment_id", sa.String(), nullable=False),
        sa.Column("relation", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("parent_id", "child_id"),
        sa.CheckConstraint("parent_id != child_id"),
        sa.ForeignKeyConstraint(["parent_id", "assessment_id"], ["evidence.id", "evidence.assessment_id"]),
        sa.ForeignKeyConstraint(
            ["child_id", "assessment_id"], ["evidence.id", "evidence.assessment_id"], ondelete="CASCADE"
        ),
    )


def downgrade():
    op.drop_table("evidence_links")
