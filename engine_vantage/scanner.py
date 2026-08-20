import ipaddress
import nmap


def validate_target(target_ip):
    try:
        ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {target_ip}") from exc


def scan_target(target_ip):
    validate_target(target_ip)
    scanner = nmap.PortScanner()

    try:
        scanner.scan(
            target_ip,
            arguments="-sV -p 21,22,80,443,445,3306,8080"
        )
    except nmap.PortScannerError as exc:
        raise RuntimeError(f"Nmap scan failed: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Unexpected scanner error: {exc}") from exc

    results = []

    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            for port in scanner[host][protocol].keys():
                service = scanner[host][protocol][port]

                if service.get("state") == "open":
                    results.append({
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "service": service.get("name", "unknown"),
                        "product": service.get("product", "unknown"),
                        "version": service.get("version", "unknown"),
                        "state": service.get("state", "unknown")
                    })

    return results
