# LFI Detection Tool

This project is an enhanced version of the original script by Ibrahim Husic, designed for detecting Local File Inclusion (LFI) vulnerabilities. The script has been extended to provide additional functionalities, including support for single URL input, Burp Suite request processing, and using a default payload file if none is provided.

## Features

- **Single URL Testing**: Test a single URL for LFI vulnerabilities directly from the command line.
- **Bulk URL Testing**: Test multiple URLs from a list.
- **Burp Suite Request Support**: Accept a request intercepted by Burp Suite and specify the parameter to test for LFI vulnerabilities.
- **Default Payloads**: If no payload file is provided, the script uses a default wordlist (`lfi_wordlist.txt`) located in the current directory.
- **Error Detection**: Identifies common LFI error patterns in the server response.
- **Multi-threading**: Optional multi-threading for faster scanning.
- **Rate Limiting**: Option to limit the rate of requests.

## Requirements

- Python 3.x
- `termcolor` module (can be installed via `pip install termcolor`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/lfi-detection-tool.git