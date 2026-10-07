"""Lock every original finding fact, including asset and reference metadata."""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("DROP TRIGGER finding_facts_immutable")
    op.execute("""
      CREATE TRIGGER finding_facts_immutable BEFORE UPDATE OF
      id, created_at, evidence_id, assessment_id, endpoint_id, affected_asset,
      rule_id, rule_version, title, category, severity, confidence,
      description, rationale, impact, remediation, "references", automated ON findings
      BEGIN SELECT RAISE(ABORT, 'Automated finding facts are immutable'); END
    """)


def downgrade():
    op.execute("DROP TRIGGER finding_facts_immutable")
    op.execute("""
      CREATE TRIGGER finding_facts_immutable BEFORE UPDATE OF
      evidence_id, assessment_id, rule_id, rule_version, title, category, severity,
      confidence, description, rationale, impact, remediation, automated ON findings
      BEGIN SELECT RAISE(ABORT, 'Automated finding facts are immutable'); END
    """)
