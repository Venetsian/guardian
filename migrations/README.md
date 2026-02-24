# WP-Guardian Database Migrations

## How It Works

Each migration is a numbered `.sql` file in this directory. The number prefix is the schema version it upgrades TO.

- `001_initial_schema.sql` — baseline (no-op, documents initial schema)
- `002_add_some_column.sql` — adds a column (upgrades schema from 1 to 2)
- `003_create_new_table.sql` — creates a new table (upgrades from 2 to 3)

The migration runner (`modules/migrator.py`) tracks the current schema version in the `schema_version` table inside the database. On each startup or update, it checks which migrations need to run and applies them in order.

## Writing a Migration

1. Create a new file with the next number: `NNN_description.sql`
2. Write SQL that is **idempotent** where possible (use `IF NOT EXISTS`, `IF EXISTS`)
3. Each statement must end with `;`
4. Add a comment at the top with the schema version

Example:

```sql
-- Migration 002: Add geoip_asn column to ip_history
-- DB Schema Version: 2

ALTER TABLE ip_history ADD COLUMN geoip_asn TEXT DEFAULT '';
```

**Note:** SQLite does not support `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so the migration runner catches "duplicate column" errors and treats them as success.

## Rules

- **Never modify an existing migration** — always create a new one
- **Never delete a migration** — old installations need them to upgrade
- **Keep migrations small** — one logical change per file
- **Test on a copy** — `cp guardian.db guardian.db.bak` before testing
- Migrations run inside a transaction — if one fails, it rolls back

## Manual Migration

```bash
# Check current schema version
python3 wp-guardian.py --db-version

# Run pending migrations manually
python3 wp-guardian.py --migrate
```
