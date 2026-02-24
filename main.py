import nmap
import json
import os



def scan_network(target_ip):
    print(f"Rozpoczynam skanowanie celu: {target_ip}...")


    nm = nmap.PortScanner()

    nm.scan(hosts=target_ip, arguments='-F -T4')

    results = {}

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            print(f"[+] Znaleziono aktywny host: {host}")
            open_ports = []

            if 'tcp' in nm[host]:
                for port in nm[host]['tcp'].keys():
                    if nm[host]['tcp'][port]['state'] == 'open':
                        open_ports.append(port)
                        print(f"    - Otwarty port: {port}")

            if open_ports:
                results[host] = open_ports

    return results



def save_scan_results(results, filename="previous_scan.json"):
    """Zapisuje wyniki skanowania do pliku JSON (tworzy Baseline)."""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\n[i] Zapisano aktualny stan sieci do pliku: {filename}")


def load_previous_scan(filename="previous_scan.json"):
    """Wczytuje poprzednie wyniki skanowania, jeśli plik istnieje."""
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            print(f"\n[i] Znaleziono poprzedni skan ({filename}). Wczytywanie...")
            return json.load(f)
    else:
        print(f"\n[i] Brak pliku {filename}. To prawdopodobnie pierwsze uruchomienie skryptu.")
        return {}




def compare_scans(previous, current):
    """Porównuje stary skan z nowym i wypisuje alerty o zmianach."""



    changes_found = False

    if not previous:
        print("[i] Brak poprzedniego skanu. Nie można wykonać porównania.")
        print("[i] Zapisuję obecny skan jako nowy punkt odniesienia (Baseline).")
        print("=" * 40 + "\n")
        return


    for host, ports in current.items():
        if host not in previous:
            print(f"[ALERT] Wykryto NOWY HOST w sieci: {host}")
            print(f"           Otwarte porty na nim: {ports}")
            changes_found = True
        else:
            new_ports = set(ports) - set(previous[host])
            if new_ports:
                print(f"[ALERT] Wykryto NOWE PORTY na hoście {host}: {list(new_ports)}")
                changes_found = True


    for host, ports in previous.items():
        if host not in current:
            print(f"[INFO] Host zniknął z sieci (nie odpowiada): {host}")
            changes_found = True
        else:
            closed_ports = set(ports) - set(current[host])
            if closed_ports:
                print(f"[INFO] Porty zostały zamknięte na hoście {host}: {list(closed_ports)}")
                changes_found = True

    if not changes_found:
        print("[OK] Nie wykryto żadnych zmian w sieci. Stan stabilny.")






if __name__ == "__main__":
    TARGET = '127.0.0.1'


    previous_results = load_previous_scan()


    current_results = scan_network(TARGET)


    compare_scans(previous_results, current_results)


    save_scan_results(current_results)