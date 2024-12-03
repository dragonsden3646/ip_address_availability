import pandas as pd
import re

# Log data
log_data = [
    '192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512',
    '203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256',
    '192.168.1.1 - - [03/Dec/2024:10:12:37 +0000] "GET /contact HTTP/1.1" 200 312',
    '198.51.100.23 - - [03/Dec/2024:10:12:38 +0000] "POST /register HTTP/1.1" 200 128',
    '203.0.113.5 - - [03/Dec/2024:10:12:39 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '192.168.1.100 - - [03/Dec/2024:10:12:40 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '10.0.0.2 - - [03/Dec/2024:10:12:41 +0000] "GET /dashboard HTTP/1.1" 200 1024',
    '198.51.100.23 - - [03/Dec/2024:10:12:42 +0000] "GET /about HTTP/1.1" 200 256',
    '192.168.1.1 - - [03/Dec/2024:10:12:43 +0000] "GET /dashboard HTTP/1.1" 200 1024',
    '203.0.113.5 - - [03/Dec/2024:10:12:44 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '203.0.113.5 - - [03/Dec/2024:10:12:45 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '192.168.1.100 - - [03/Dec/2024:10:12:46 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '10.0.0.2 - - [03/Dec/2024:10:12:47 +0000] "GET /profile HTTP/1.1" 200 768',
    '192.168.1.1 - - [03/Dec/2024:10:12:48 +0000] "GET /home HTTP/1.1" 200 512',
    '198.51.100.23 - - [03/Dec/2024:10:12:49 +0000] "POST /feedback HTTP/1.1" 200 128',
    '203.0.113.5 - - [03/Dec/2024:10:12:50 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '192.168.1.1 - - [03/Dec/2024:10:12:51 +0000] "GET /home HTTP/1.1" 200 512',
    '198.51.100.23 - - [03/Dec/2024:10:12:52 +0000] "GET /about HTTP/1.1" 200 256',
    '203.0.113.5 - - [03/Dec/2024:10:12:53 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '192.168.1.100 - - [03/Dec/2024:10:12:54 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '10.0.0.2 - - [03/Dec/2024:10:12:55 +0000] "GET /contact HTTP/1.1" 200 512',
    '198.51.100.23 - - [03/Dec/2024:10:12:56 +0000] "GET /home HTTP/1.1" 200 512',
    '192.168.1.100 - - [03/Dec/2024:10:12:57 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '203.0.113.5 - - [03/Dec/2024:10:12:58 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '10.0.0.2 - - [03/Dec/2024:10:12:59 +0000] "GET /dashboard HTTP/1.1" 200 1024',
    '192.168.1.1 - - [03/Dec/2024:10:13:00 +0000] "GET /about HTTP/1.1" 200 256',
    '198.51.100.23 - - [03/Dec/2024:10:13:01 +0000] "POST /register HTTP/1.1" 200 128',
    '203.0.113.5 - - [03/Dec/2024:10:13:02 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '192.168.1.100 - - [03/Dec/2024:10:13:03 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"',
    '10.0.0.2 - - [03/Dec/2024:10:13:04 +0000] "GET /profile HTTP/1.1" 200 768',
    '198.51.100.23 - - [03/Dec/2024:10:13:05 +0000] "GET /about HTTP/1.1" 200 256',
    '192.168.1.1 - - [03/Dec/2024:10:13:06 +0000] "GET /home HTTP/1.1" 200 512',
    '198.51.100.23 - - [03/Dec/2024:10:13:07 +0000] "POST /feedback HTTP/1.1" 200 128'
]

# Creating a DataFrame
df = pd.DataFrame(log_data, columns=["log"])

# Extracting IP addresses
df['ip'] = df['log'].str.extract(r'^(\d+\.\d+\.\d+\.\d+)')

# Extracting endpoints correctly, excluding HTTP version
df['endpoint'] = df['log'].str.extract(r'\"[A-Z]+\s(/[^"]+)')



# Count requests per IP
ip_counts = df['ip'].value_counts().reset_index()
ip_counts.columns = ['IP Address', 'Request Count']
ip_counts = ip_counts.sort_values(by='Request Count', ascending=False)

# Identifying most frequently accessed endpoint
endpoint_counts = df['endpoint'].value_counts().reset_index()
endpoint_counts.columns = ['Endpoint', 'Access Count']
most_accessed_endpoint = endpoint_counts.iloc[0]

# Identifying potential brute force login attempts (failed login attempts - status code 401)
failed_login_threshold = 10
failed_logins = df[df['log'].str.contains(r'POST /login', case=False) & df['log'].str.contains(r'401')]
failed_login_counts = failed_logins['ip'].value_counts().reset_index()
failed_login_counts.columns = ['IP Address', 'Failed Login Attempts']

# Flagging IPs with failed login attempts exceeding the threshold
suspicious_ips = failed_login_counts[failed_login_counts['Failed Login Attempts'] > failed_login_threshold]

# Output results
print("IP Address           Request Count")
for _, row in ip_counts.iterrows():
    print(f"{row['IP Address']:20} {row['Request Count']}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint['Endpoint']} (Accessed {most_accessed_endpoint['Access Count']} times)")

print("\nSuspicious Activity Detected:")
if not suspicious_ips.empty:
    for _, row in suspicious_ips.iterrows():
        print(f"{row['IP Address']:20} {row['Failed Login Attempts']} failed attempts")
else:
    print("No suspicious activity detected.")

# Saving results to CSV
with open('log_analysis_results.csv', 'w', newline='') as f:
    # Writing requests per IP
    ip_counts.to_csv(f, index=False)
    f.write("\nMost Accessed Endpoint:\n")
    f.write(f"{most_accessed_endpoint['Endpoint']} (Accessed {most_accessed_endpoint['Access Count']} times)\n")
    f.write("\nSuspicious Activity Detected:\n")
    if not suspicious_ips.empty:
        suspicious_ips.to_csv(f, index=False)
    else:
        f.write("No suspicious activity detected.\n")
