import re
from urllib.parse import urlparse

def is_ip_address(domain):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) is not None

def analyze_url(url):
    parsed = urlparse(url)

    score = 0
    issues = []

    # Check protocol
    if parsed.scheme != "https":
        issues.append("Does not use HTTPS.")
    else:
        score += 1

    # Check if domain is an IP address
    domain = parsed.netloc.split(':')[0]  # remove port if any
    if is_ip_address(domain):
        issues.append("Uses IP address instead of domain name.")
    else:
        score += 1

    # Check length
    if len(url) > 75:
        issues.append("URL is very long.")
    else:
        score += 1

    # Check for suspicious symbols
    if "@" in url:
        issues.append("Contains '@' symbol (used to hide real domain).")
    if "//" in url[8:]:  # after 'https://'
        issues.append("Contains multiple '//' (can be used to confuse users).")
    if "-" in domain:
        issues.append("Domain contains '-' (sometimes used in fake domains).")

    # Check number of subdomains
    subdomains = domain.split('.')
    if len(subdomains) > 3:
        issues.append("Too many subdomains (may be suspicious).")
    else:
        score += 1

    # Final result
    if score >= 4:
        result = "URL looks safe ✅"
    elif score >= 2:
        result = "URL may be suspicious ⚠️"
    else:
        result = "URL is likely malicious ❌"

    return result, issues

# Example usage
if __name__ == "__main__":
    url = input("Enter URL to scan: ")
    result, issues = analyze_url(url)

    print(f"\nAnalysis result: {result}")
    if issues:
        print("Potential issues:")
        for issue in issues:
            print(" -", issue)
