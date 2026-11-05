import sys
from pathlib import Path

def generate_prompt(chunk_id, track, input_path, output_path):
    template = Path("docs/templates/CHUNK_WORKER_PROMPT.md").read_text()
    prompt = (template
              .replace("{{CHUNK_ID}}", chunk_id)
              .replace("{{TRACK}}", track)
              .replace("{{INPUT_CHUNK_PATH}}", input_path)
              .replace("{{OUTPUT_RESULT_PATH}}", output_path))
    return prompt

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python format_chunk_prompt.py <chunk_id> <track> <input_path> <output_path>")
        sys.exit(1)
    print(generate_prompt(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]))
