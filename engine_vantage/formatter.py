def make_readable(results):
    readable = []

    for result in results:
        service = result["service"]
        version = result["version"]

        readable.append({
            "Host": result["host"],
            "Port": result["port"],
            "Protocol": result["protocol"].upper(),
            "Service": service.capitalize(),
            "Version": version if version else "Unknown",
            "State": result["state"].upper(),
            "Summary": (
                f"{service.capitalize()} running on port "
                f"{result['port']} — version {version}"
            )
        })

    return readable
