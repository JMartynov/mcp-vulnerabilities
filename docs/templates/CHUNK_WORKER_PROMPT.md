# MCP Dual-Axis Audit - Chunk Worker Contract

## Objective
Execute the Dual-Axis Trivy Audit on Chunk `{{CHUNK_ID}}` within Track `{{TRACK}}`.

## Instructions

1. **Run the Audit**
   Execute the chunk runner script for this specific chunk:
   ```bash
   python scripts/run_chunk_audit.py --chunk {{INPUT_CHUNK_PATH}} --output {{OUTPUT_RESULT_PATH}}
   ```

2. **Validate the Output**
   Run the pytest suite to ensure your output strictly complies with the `DualAxisSecurityAssessment` schema and item counts match:
   ```bash
   pytest tests/test_chunk_validation.py
   ```

3. **Commit Results**
   Commit the generated `{{OUTPUT_RESULT_PATH}}` with a descriptive message like:
   `chore(audit): complete {{TRACK}} {{CHUNK_ID}}`

## Directives
- **Non-Interactive Completion Directive**: Do not ask for user input. Execute the steps, ensure validation passes, and commit the changes directly. If validation fails, attempt to resolve the schema/timeout errors automatically before committing.
