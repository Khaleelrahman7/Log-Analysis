import re
import csv
from collections import defaultdict

# Configuration
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = r'C:\Users\Admin\OneDrive\Pictures\Desktop\Log Analysis\sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'

def parse_log_file(log_file):
    ip_requests = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Extracting IP address
            ip_match = re.match(r'(\S+) - -', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_requests[ip_address] += 1

            # Extracting the endpoint and status code
            endpoint_match = re.search(r'"(?:GET|POST) (\S+) HTTP/\d\.\d" (\d+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                status_code = endpoint_match.group(2)
                endpoint_counts[endpoint] += 1

                # Checking for failed login attempts
                if status_code == '401' or 'Invalid credentials' in line:
                    failed_logins[ip_address] += 1

    return ip_requests, endpoint_counts, failed_logins

def analyze_data(ip_requests, endpoint_counts, failed_logins):
    # Sorting IP requests
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

    # Finding the most accessed endpoint
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1], default=(None, 0))

    # Detecting suspicious activity
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    return sorted_ip_requests, most_accessed_endpoint, suspicious_activity

def output_results(sorted_ip_requests, most_accessed_endpoint, suspicious_activity):
    # for Printing results to terminal
    print("IP Address           Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Check for suspicious activity
    if suspicious_activity:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count}")
    else:
        print("\nNo suspicious activity detected.")

    # For Saving results to CSV
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(sorted_ip_requests)

        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        if suspicious_activity:
            writer.writerow(['IP Address', 'Failed Login Count'])
            for ip, count in suspicious_activity.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(['No suspicious activity detected'])

def main():
    ip_requests, endpoint_counts, failed_logins = parse_log_file(LOG_FILE)
    sorted_ip_requests, most_accessed_endpoint, suspicious_activity = analyze_data(ip_requests, endpoint_counts, failed_logins)
    output_results(sorted_ip_requests, most_accessed_endpoint, suspicious_activity)

if __name__ == "__main__":
    main()
