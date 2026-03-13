import csv
import random
from datetime import datetime, timedelta

ips = [
    "192.168.1.10","45.33.12.90","74.22.81.19","185.23.92.18",
    "103.44.221.10","210.18.90.77","95.120.45.201","61.77.14.55",
    "150.145.167.64","172.16.5.12"
]

cities = ["New York","Tokyo","Berlin","London","Singapore","Sydney","Paris","Seoul"]

users = ["root","admin","ubuntu","ec2-user"]

services = ["ssh","sudo","cron","su"]

protocols = ["SSH2","TELNET"]

start_time = datetime(2024,1,1)

rows = []

for i in range(1000):

    timestamp = start_time + timedelta(minutes=random.randint(0,1440))

    row = [
        timestamp.isoformat(),
        random.choice(ips),
        random.choice(cities),
        random.choice(users),
        random.choice(services),
        1,
        "Failed" if random.random() < 0.8 else "Success",
        random.choice([22,80,443,2222]),
        random.choice(protocols)
    ]

    rows.append(row)

with open("data/sample_log.csv","w",newline="") as f:

    writer = csv.writer(f)

    writer.writerow([
        "timestamp","source_ip","city","username",
        "service","attempts","status","port","protocol"
    ])

    writer.writerows(rows)

print("Sample log dataset generated.")