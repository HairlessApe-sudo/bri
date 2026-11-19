"""Table manifest for the repository's additive, schema-qualified table DDL."""
import re


def declared_tables(files):
    # Current migrations declare permanent tables literally on their own line.
    # Renames/drops need an explicit manifest update, not a looser live assertion.
    tables = set()
    create = re.compile(r'^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?bri\.([a-z_][a-z0-9_]*)\s*\(', re.IGNORECASE | re.MULTILINE)
    for path in files:
        text = path.read_text(encoding='utf-8')
        if re.search(r'^\s*(?:DROP\s+TABLE\b|ALTER\s+TABLE\s+bri\.\w+\s+RENAME\s+TO\b)', text, re.IGNORECASE | re.MULTILINE):
            raise ValueError('explicit catalog manifest support required for table drop or rename')
        tables.update(name.lower() for name in create.findall(text))
    tables.remove('schema_migrations')
    return tables
