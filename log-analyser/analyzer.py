import sys
import csv
import matplotlib.pyplot as plt
import time 


TOP_RESULTS = 50
ALERT_THRESHOLD = 150

def extract_failed_logins(auth_log):  
# Dictionary to store attack counts
    attack_counts = {}

    total_events = 0
    total_failed= 0 

    with open(auth_log, newline="", encoding= "utf-8") as file:

        reader= csv.DictReader(file)

        for entry in reader:
                total_events +=1 

                if entry["status"].lower() == "failed":

                    total_failed +=1 

                    ip = entry["source_ip"]

                    attack_counts[ip] = attack_counts.get(ip, 0) + 1

    return attack_counts, total_events, total_failed


def find_top_attackers(attack_counts):

    top_ip = None
    max_attempts = 0 
    
    for ip, count in attack_counts.items():
        if count > max_attempts:
            max_attempts = count
            top_ip = ip

    print("\nTop Attacker: ")
    print (f"{top_ip} - {max_attempts} attempts")
    
    return (top_ip, max_attempts)


def detect_bruteforce(attack_counts):

    results= []

    sorted_attackers = sorted(
        attack_counts.items(),
        key= lambda x: x[1], 
        reverse =True)
    
    top_attackers= sorted_attackers[:TOP_RESULTS]
        
    for ip, count in top_attackers:

        if count >= 100:
            risk = "HIGH RISK"
        elif count >= 50:
            risk ="MEDIUM RISK"
        else: 
            risk = "LOW RISK"
           

        message= f"{ip} - {count} failed attempts {risk}\n"

        print(message)
        results.append(message)

    return results


def detect_attack_alerts(attack_counts):


    print("\nSecurity Alerts")
    print("----------------")

    for ip, count in attack_counts.items():

        if count >= ALERT_THRESHOLD:

            print(f"ALERT: Possible Brute Force Attack Detected")
            print(f"IP Address: {ip}")
            print(f"Failed Attempts: {count}\n")


def find_most_targeted_username(entries):

    username_counts = {}

    for entry in entries:

        if entry["status"].lower() == "failed": 

            username =entry["username"]
            attempt = int(entry["attempts"])

            if username in username_counts:
                username_counts[username] += attempt
            else:
                username_counts[username] = attempt 

    most_targeted = max(username_counts, key= username_counts.get)

    print("\nMost Targeted Username: ")
    print(f"{most_targeted} - {username_counts[most_targeted]} attempts")

    return username_counts


def analyze_attack_locations(auth_log):

    city_counts= {}
    
    with open(auth_log, newline="") as file:

        reader= csv.DictReader(file)

        for entry in reader:

                if entry["status"].lower() == "failed":

                    city = entry["city"]

                    city_counts[city] = city_counts.get(city, 0) + 1

    return city_counts


def show_top_cities(city_counts):

    sorted_cities = sorted(
        city_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )

    top_cities = sorted_cities[:TOP_RESULTS]

    print("\nTop Attack Locations")
    print("--------------------")

    for city, count in top_cities:
        print(f"{city} → {count} failed attempts")

    return top_cities


def export_attackers_csv(attack_counts):

    sorted_attackers = sorted(
        attack_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )

    with open("top_attackers.csv", "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow(["IP Address", "Failed Attempts"])

        for ip, count in sorted_attackers[:TOP_RESULTS]:
            writer.writerow([ip, count])


def visualize_attackers(attack_counts):

    sorted_attackers = sorted(
        attack_counts.items(),
        key= lambda x: x[1], 
        reverse =True)
    
    top_attackers = sorted_attackers[:10]
        
    ips = [x[0] for x in top_attackers]
    attempts = [x[1] for x in top_attackers]

    plt.figure(figsize=(10,6))
    plt.bar(ips, attempts)

    plt.title("Failed Login Attempts per IP")
    plt.xlabel("Source IP")
    plt.ylabel("No of Failed Attempts")

    plt.xticks(rotation=45)
    plt.tight_layout()

    plt.show()


def visualize_cities(city_counts):

    sorted_cities = sorted(
        city_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )

    top_cities = sorted_cities[:10]

    cities = [x[0] for x in top_cities]
    attempts = [x[1] for x in top_cities]

    plt.figure(figsize=(10,6))
    plt.bar(cities, attempts)

    plt.title("Top Attack Locations")
    plt.xlabel("City")
    plt.ylabel("Failed Login Attempts")

    plt.xticks(rotation=45)
    plt.tight_layout()

    plt.show()


def analyze_attack_timeline(auth_log):

    hourly_counts = {}

    with open(auth_log, newline="", encoding="utf-8") as file:

        reader = csv.DictReader(file)

        for entry in reader:

            if entry["status"].lower() == "failed":

                hour = entry["timestamp"][11:13]

                hourly_counts[hour] = hourly_counts.get(hour, 0) + 1

    sorted_hours = sorted(hourly_counts.items())

    hours = [x[0] for x in sorted_hours]
    attempts = [x[1] for x in sorted_hours]

    plt.figure(figsize=(10,6))

    plt.plot(hours, attempts)

    plt.title("Failed Login Attempts by Hour")
    plt.xlabel("Hour of Day")
    plt.ylabel("Failed Attempts")

    plt.tight_layout()
    plt.show()


def monitor_logs(log_file):

    print("Starting real-time monitoring...\n")

    seen_ips = {}

    with open(log_file, "r", encoding="utf-8") as file:

        file.seek(0,2)   # move to end of file

        while True:

            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            if "Failed" in line:

                parts = line.split(",")

                ip = parts[1]

                seen_ips[ip] = seen_ips.get(ip,0) + 1

                if seen_ips[ip] > 10:

                    print("🚨 ALERT: Possible brute force attack")
                    print(f"IP: {ip}")
                    print(f"Attempts: {seen_ips[ip]}\n")


def write_report(results, attacks, total_events, total_failed, attack_counts):
 
    with open('security_report.txt', 'w') as report:
        report.write("Security Log Analysis Report\n")
        report.write("--------------------------------\n\n")

        report.write("Summary\n")
        report.write("---------\n\n")
        report.write(f"Total Events Processed: {total_events}\n")
        report.write(f"Total Failed Logins: {total_failed}\n")
        report.write(f"Unique Attackers IP: {len(attack_counts)}\n")

        report.write("\nTop Attacker\n")
        report.write(f"{attacks[0]} - {attacks[1]} attempts")

        report.write("\nTop Attackers\n")
        report.write("---------\n\n")

        for line in results:
            report.write(line +"\n")


def main():

    if len(sys.argv) < 2:
        print("Usage:")
        print("python analyzer.py analyze <log_file>")
        print("python analyzer.py monitor <log_file>")
        print("python analyzer.py dashboard")
        sys.exit(1)

    command = sys.argv[1]

    if command == "analyze":

        log_file = sys.argv[2]

        attack_counts, total_events, total_failed = extract_failed_logins(log_file)

        results = detect_bruteforce(attack_counts)

        attacks = find_top_attackers(attack_counts)

        city_counts = analyze_attack_locations(log_file)

        show_top_cities(city_counts)

        analyze_attack_timeline(log_file)

        visualize_attackers(attack_counts)

        visualize_cities(city_counts)

        export_attackers_csv(attack_counts)

        write_report(results, attacks, total_events, total_failed, attack_counts)


    elif command == "monitor":

        log_file = sys.argv[2]

        monitor_logs(log_file)


    elif command == "dashboard":

        import os
        os.system("streamlit run dashboard.py")


    else:

        print("Unknown command")


if __name__ == "__main__":
    main()





    