import requests

def check_security_headers(url):
    # Common security headers to verify
    required_headers = {
        "Strict-Transport-Security": "Forces HTTPS connections to prevent MITM attacks.",
        "Content-Security-Policy": "Helps prevent XSS and data injection attacks.",
        "X-Content-Type-Options": "Prevents MIME-sniffing vulnerabilities.",
        "X-Frame-Options": "Protects against clickjacking attacks.",
        "Referrer-Policy": "Controls how much referrer information is sent.",
        "Permissions-Policy": "Manages access to browser features like camera, microphone, etc.",
        "X-XSS-Protection": "Provides basic protection against reflected XSS (legacy header)."
    }

    try:
        # Send GET request
        response = requests.get(url, timeout=10)
        headers = response.headers

        print(f"\n[*] Scanning Security Headers for: {url}\n")
        missing_headers = []

        # Check presence of each header
        for header, description in required_headers.items():
            if header in headers:
                print(f"[+] {header}: Present")
            else:
                print(f"[-] {header}: Missing")
                missing_headers.append((header, description))

        # Show summary
        if missing_headers:
            print("\n⚠️ Missing Headers Summary:")
            for header, description in missing_headers:
                print(f" - {header}: {description}")
        else:
            print("\n✅ All recommended security headers are present.")

    except requests.exceptions.RequestException as e:
        print(f"\n[!] Error: Could not fetch headers from {url}\nReason: {e}")


if __name__ == "__main__":
    print("=== HTTP Security Header Checker ===")
    target_url = input("Enter target URL (e.g., https://example.com): ").strip()

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    check_security_headers(target_url)
    input("\nPress Enter to exit...")
