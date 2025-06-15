import os

def clean_preserve_lines(input_path, output_path):
    with open(input_path, 'r') as f:
        lines = f.readlines()

    clean_lines = []
    for line in lines:
        if any(keyword in line for keyword in [
            "@vulnerable_at_lines",
            "@source",
            "@author"
        ]):
            # Replace with a blank comment line to preserve line count
            clean_lines.append("// [removed annotation]\n")
        else:
            clean_lines.append(line)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        f.writelines(clean_lines)

# Example usage
from glob import glob

input_files = glob("smartbugs-curated/dataset/**/*.sol", recursive=True)
for in_file in input_files:
    out_file = in_file.replace("smartbugs-curated", "cleaned-smartbugs")
    clean_preserve_lines(in_file, out_file)