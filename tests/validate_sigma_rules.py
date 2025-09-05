import yaml
import json
import jsonschema
import os

# Load schema
with open('tests/sigma.schema.json') as f:
    schema = json.load(f)

# Get list of filenames
filenames = [f for f in os.listdir('.') if f.endswith('.yml') or f.endswith('.yaml')]
list_of_rules = []

# Load and validate a YAML rule
for filename in filenames:
    with open(filename) as f:
        rule = yaml.safe_load(f)
        list_of_rules.append(rule)

validator = jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())

for rule, filename in zip(list_of_rules, filenames):
    errors = list(validator.iter_errors(rule))
    if not errors:
        print(f"VALID: '{filename}'")
    else:
        for error in errors:
            print(f"INVALID: '{filename}' - {error.message}")