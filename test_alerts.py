
from alerts import analyze_connections

test_connections = [
    {"remote": "8.8.8.8:3389"},
    {"remote": "192.168.1.10:445"},
    {"remote": "8.8.8.8:443"}
]

results = analyze_connections(test_connections)

print("\n===== FIREWALL SECURITY TEST =====")

for alert in results:
    print("IP:", alert["ip"])
    print("Type:", alert["type"])
    print("Severity:", alert["severity"])
    print("Message:", alert["message"])
    print("----------------------------")
