import os
import google.generativeai as genai
from pathlib import Path
import json
import re

# Configure the Gemini API
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
if not GOOGLE_API_KEY:
    raise ValueError("Please set the GOOGLE_API_KEY environment variable")

genai.configure(api_key=GOOGLE_API_KEY)

# Initialize the Gemini model
model = genai.GenerativeModel('gemini-2.0-flash')

def read_solidity_file(file_path):
    """Read a Solidity file and return its contents."""
    with open(file_path, 'r') as file:
        return file.read()

def clean_json_response(response_text):
    """Clean the response text by removing markdown formatting."""
    # Remove markdown code block markers
    cleaned = re.sub(r'```json\n|\n```', '', response_text)
    # Remove any leading/trailing whitespace
    cleaned = cleaned.strip()
    return cleaned

def validate_line_numbers(vulnerabilities, contract_content):
    """Validate that reported line numbers exist in the contract."""
    total_lines = len(contract_content.splitlines())
    valid_vulnerabilities = []
    invalid_vulnerabilities = []
    
    for vuln in vulnerabilities:
        line_num = vuln.get('line')
        if isinstance(line_num, int) and 1 <= line_num <= total_lines:
            valid_vulnerabilities.append(vuln)
        else:
            invalid_vulnerabilities.append({
                'vulnerability': vuln,
                'reason': f'Line number {line_num} is out of range (1-{total_lines})'
            })
    
    return valid_vulnerabilities, invalid_vulnerabilities

def analyze_contract(contract_content):
    """Analyze a Solidity contract using Gemini."""
    try:
        # System prompt for vulnerability detection
        system_prompt = """You are a Solidity security auditor.

Analyze the following Solidity smart contract and return **only actual vulnerabilities** — not stylistic or best-practice issues.

Report vulnerabilities in **strict JSON** format using this structure:

[
  {
    "line": <line number>,
    "category": "<category name>",
    "reason": "<brief explanation of why this is a vulnerability>"
  }
]

### Rules:
- Do NOT include "possible", "maybe", or "uncertain" issues.
- Only include bugs that match one of these categories:
    - access_control
    - arithmetic
    - reentrancy
    - denial_of_service
    - time_manipulation
    - bad_randomness
    - unchecked_low_level_calls
    - front_running
    - short_addresses
    - other (ONLY if it's clearly a security bug not covered above)

- Line numbers must refer to the exact line in the contract where the vulnerability appears.
- If there are no vulnerabilities, return: []

Now, analyze this contract:
"""

        # Combine system prompt and contract content
        prompt = f"{system_prompt}\n{contract_content}"
        
        # Generate response
        response = model.generate_content(prompt)
        
        # Try to parse the response as JSON
        try:
            # Clean the response text before parsing
            cleaned_response = clean_json_response(response.text)
            vulnerabilities = json.loads(cleaned_response)
            
            # Validate line numbers
            valid_vulns, invalid_vulns = validate_line_numbers(vulnerabilities, contract_content)
            
            return {
                'status': 'success',
                'vulnerabilities': valid_vulns,
                'validation': {
                    'total_lines': len(contract_content.splitlines()),
                    'invalid_vulnerabilities': invalid_vulns
                }
            }
        except json.JSONDecodeError as e:
            return {
                'status': 'error',
                'error': f'Failed to parse response as JSON: {str(e)}',
                'raw_response': response.text,
                'cleaned_response': cleaned_response
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

def main():
    dataset_dir = Path('smartbugs-curated/dataset')
    output_dir = Path('analysis_results')
    output_dir.mkdir(exist_ok=True)

    for vuln_type in dataset_dir.iterdir():
        if vuln_type.is_dir():
            print(f"\nAnalyzing contracts in {vuln_type.name}...")
            vuln_output_dir = output_dir / vuln_type.name
            vuln_output_dir.mkdir(exist_ok=True)

            for contract_file in vuln_type.glob('*.sol'):
                # Check if analysis already exists
                output_file = vuln_output_dir / f"{contract_file.stem}.json"
                if output_file.exists():
                    print(f"Skipping {contract_file.name} - already analyzed")
                    continue

                print(f"Analyzing {contract_file.name}...")
                contract_content = read_solidity_file(contract_file)
                result = analyze_contract(contract_content)

                with open(output_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Analysis saved to {output_file}")

if __name__ == "__main__":
    main()