
# Log File Analysis Tool

A Python script for analyzing web server log files to extract insights such as:
- Number of requests per IP address
- The most accessed endpoint
- Detection of suspicious activity (e.g., repeated failed login attempts)

## Features

- **Parse and Analyze Logs**: Extracts IP addresses, endpoints, and HTTP status codes from the log file.
- **Suspicious Activity Detection**: Identifies IP addresses with more than 10 failed login attempts.
- **CSV Output**: Saves the analysis results into a CSV file for further review.
- **Customizable Settings**: Configure log file input and thresholds easily.

## Requirements

- Python 3.6+
- Libraries: `re`, `csv`, `collections`

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/Khaleelrahman7/Log-Analysis/log-analysis-tool.git
   cd log-analysis-tool
   ```

2. Place your log file in the same directory as the script and name it `sample.log` (or update the `LOG_FILE` variable in the script to the desired file name).

3. Run the script:
   ```bash
   python log_analysis_tool.py
   ```

4. Check the terminal output for a summary of the results.

5. Review the detailed analysis in the generated CSV file (`log_analysis_results.csv`).

## Configuration

Modify the following variables in the script to customize its behavior:
- `LOG_FILE`: Path to the log file to analyze.
- `FAILED_LOGIN_THRESHOLD`: Threshold for detecting suspicious activity (default is 10 failed login attempts).
- `OUTPUT_CSV`: Name of the output CSV file (default is `log_analysis_results.csv`).

## Output

The script generates the following:
- **Terminal Output**:
  - List of IP addresses and their request counts.
  - Most accessed endpoint.
  - List of suspicious IP addresses with failed login counts.
- **CSV File**:
  - Requests per IP
  - Most accessed endpoint
  - Suspicious activity

## Example

### Input Log File (`sample.log`)
```
192.168.1.1 - - [01/Dec/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 -
192.168.1.2 - - [01/Dec/2024:10:01:00 +0000] "POST /login HTTP/1.1" 401 Invalid credentials
...
```

### Terminal Output
```
IP Address           Request Count
192.168.1.1          15
192.168.1.2          8

Most Frequently Accessed Endpoint:
/index.html (Accessed 10 times)

Suspicious Activity Detected:
IP Address           Failed Login Attempts
192.168.1.2          12
```

### CSV Output (`log_analysis_results.csv`)
Refer to the file generated for detailed results.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests to enhance this tool.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Author

Developed by [Your Name](https://github.com/your-username).


