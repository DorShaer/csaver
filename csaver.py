import asyncio
import json
import argparse
from typing import Dict, List, Tuple
import aiohttp
from termcolor import colored
import chardet
import sys
import re
from urllib.parse import urlparse

class Crawler:
    def __init__(self, base_url: str, har_file: str, verbose: bool, test_all_extensions: bool):
        """
        A robust crawler that:
        - Loads a HAR file
        - Extracts all URLs starting with a given base_url
        - Lets you choose which domains to include in scope
        - Fetches each URL without auth, checking for:
          * Non-200 responses (protected resources)
          * Client-side redirects in HTML/text responses
        - Gracefully handles binary responses and decoding errors
        - Provides detailed, color-coded reporting of results

        Additional Features:
        - Verbose mode: If off, only print the method and URL of protected/redirecting resources.
        - Test all extensions: If off, skip common static resources by extension.
        """
        self.base_url = base_url
        self.har_file = har_file
        self.verbose = verbose
        self.test_all_extensions = test_all_extensions

        self.session = None
        self.auth_headers = {}
        self.har_data = {}
        self.request_map = {}
        self.links = []

        # Patterns to detect client-side redirects
        self.client_side_redirect_patterns = {
            "Meta refresh": re.compile(
                r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\'][^"]*url\s*=\s*([^"\'\s]+)',
                re.IGNORECASE
            ),
            "Window location": re.compile(r'window\.location\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
            "Location href": re.compile(r'location\.href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
            "Location replace": re.compile(r'location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)', re.IGNORECASE),
            "Location assign": re.compile(r'location\.assign\s*\(\s*["\']([^"\']+)["\']\s*\)', re.IGNORECASE),
            "Document location": re.compile(r'document\.location\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
            # JS redirects triggered by timeouts
            "setTimeout redirect": re.compile(
                r'setTimeout\s*\(\s*function\s*\(\)\s*\{\s*(?:window\.location|location\.href|document\.location)[^}]+\}\s*,\s*\d+\s*\)',
                re.IGNORECASE
            ),
            "setInterval redirect": re.compile(
                r'setInterval\s*\(\s*function\s*\(\)\s*\{\s*(?:window\.location|location\.href|document\.location)[^}]+\}\s*,\s*\d+\s*\)',
                re.IGNORECASE
            )
        }

        # Common static file extensions to skip unless --test-all-extensions is specified
        self.ignored_extensions = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map', '.svg'}

    async def load_har_file(self):
        """
        Load and decode HAR file, store in self.har_data.
        """
        try:
            with open(self.har_file, 'rb') as f:
                data = f.read()
            encoding = chardet.detect(data)['encoding']
            self.har_data = json.loads(data.decode(encoding))
        except Exception as e:
            print(colored(f"Error reading HAR file: {e}", "red", attrs=["bold"]), flush=True)
            sys.exit(1)

    async def get_headers_and_cookies_from_har(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Extract headers and cookies from the HAR file.
        """
        headers = {}
        cookies = {}
        for entry in self.har_data.get('log', {}).get('entries', []):
            request = entry.get('request', {})
            # Extract headers
            for header in request.get('headers', []):
                headers[header.get('name', '')] = header.get('value', '')
            # Extract cookies
            for cookie in request.get('cookies', []):
                cookies[cookie.get('name', '')] = cookie.get('value', '')
        return headers, cookies

    async def extract_links_from_har(self) -> List[str]:
        """
        Extract URLs starting with base_url from HAR.
        Store request details for reporting.
        """
        links = []
        entries = self.har_data.get('log', {}).get('entries', [])
        for entry in entries:
            request = entry.get('request', {})
            url = request.get('url', '')
            method = request.get('method', 'GET')

            if url.startswith(self.base_url):
                links.append(url)
                self.request_map[url] = {
                    'method': method,
                    'headers': {h['name']: h['value'] for h in request.get('headers', [])},
                    'cookies': {c['name']: c['value'] for c in request.get('cookies', [])}
                }

        return list(set(links))

    def get_unique_domains(self, links: List[str]) -> List[str]:
        """
        Extract unique domains from URLs.
        """
        domains = set()
        for link in links:
            parsed = urlparse(link)
            if parsed.netloc:
                domains.add(parsed.netloc)
        return sorted(domains)

    def prompt_domain_selection(self, domains: List[str]) -> List[str]:
        """
        Prompt user to select domains by index or 'all'.
        """
        print(colored("\nFound the following domains:", "green", attrs=["bold"]), flush=True)
        for i, d in enumerate(domains, start=1):
            print(f"{i}. {d}", flush=True)

        selection = input(colored("\nSelect domains by index (e.g. 1,3,5 or 1-5 or 'all'), or press Enter to select all: ", "yellow", attrs=["bold"]))
        
        selection = selection.strip().lower()
        if selection == "" or selection == "all":
            return domains
        else:
            chosen = []
            parts = selection.split(',')
            for part in parts:
                part = part.strip()
                if re.match(r'^\d+$', part):
                    idx = int(part)
                    if 1 <= idx <= len(domains):
                        chosen.append(domains[idx-1])
                elif re.match(r'^\d+-\d+$', part):
                    start_str, end_str = part.split('-')
                    start_idx, end_idx = int(start_str), int(end_str)
                    if 1 <= start_idx <= len(domains) and 1 <= end_idx <= len(domains):
                        for i in range(start_idx, end_idx+1):
                            chosen.append(domains[i-1])
                else:
                    print(colored(f"Invalid selection: {part}", "red", attrs=["bold"]), flush=True)

            chosen = list(set(chosen))
            if not chosen:
                print(colored("No valid domains selected. Exiting.", "red", attrs=["bold"]), flush=True)
                sys.exit(0)
            return chosen

    def should_skip_url(self, url: str) -> bool:
        """
        Determine if a URL should be skipped based on its extension.
        If --test-all-extensions is not set, skip common static resource extensions.
        """
        if self.test_all_extensions:
            return False
        parsed = urlparse(url)
        path = parsed.path.lower()
        for ext in self.ignored_extensions:
            if path.endswith(ext):
                return True
        return False

    async def report_protected_resource(self, link: str, trigger_cause: str, resp: aiohttp.ClientResponse, redirect_details: Dict[str, str]=None):
        """
        Report info about a protected or redirecting resource.
        If verbose is off: print only "METHOD - URL"
        If verbose is on: print full detailed info.
        """
        req_details = self.request_map.get(link, {})
        req_method = req_details.get('method', 'GET')

        if not self.verbose:
            # Just print "METHOD - URL"
            print(f"{req_method} - {link}", flush=True)
        else:
            # Verbose mode: print the full report
            status = resp.status
            reason = resp.reason or ''
            resp_headers = dict(resp.headers)

            print(colored("\nPotentially protected or redirecting resource found!", "green", attrs=["bold"]), flush=True)
            print(colored(f"URL: {link}", "cyan", attrs=["bold"]), flush=True)
            print(colored(f"Method: {req_method}", "cyan"), flush=True)
            print(colored(f"Status: {status} {reason}", "cyan"), flush=True)
            print(colored(f"Trigger Cause: {trigger_cause}", "yellow"), flush=True)

            if redirect_details:
                print(colored("Client-side Redirect Detected:", "yellow", attrs=["bold"]), flush=True)
                for detail, val in redirect_details.items():
                    print(f"  {detail}: {val}", flush=True)
                print(colored("This suggests the page may be protected by a client-side script redirecting you to a login or another protected area.", "yellow", attrs=["bold"]), flush=True)

            req_headers = req_details.get('headers', {})
            req_cookies = req_details.get('cookies', {})

            if req_headers:
                print(colored("Request Headers:", "magenta", attrs=["bold"]), flush=True)
                for k, v in req_headers.items():
                    print(f"  {k}: {v}", flush=True)

            if req_cookies:
                print(colored("Request Cookies:", "magenta", attrs=["bold"]), flush=True)
                for k, v in req_cookies.items():
                    print(f"  {k}: {v}", flush=True)

            if resp_headers:
                print(colored("Response Headers:", "magenta", attrs=["bold"]), flush=True)
                for k, v in resp_headers.items():
                    print(f"  {k}: {v}", flush=True)

            print("-" * 80, flush=True)

    def detect_client_side_redirect(self, html: str) -> Tuple[bool, str, Dict[str, str]]:
        """
        Analyze HTML for client-side redirects using defined regex patterns.
        """
        for cause, pattern in self.client_side_redirect_patterns.items():
            match = pattern.search(html)
            if match:
                redirect_url = match.group(1).strip() if match.groups() else "Unknown"
                details = {
                    "Redirect Pattern": cause,
                    "Redirect Target": redirect_url
                }
                return True, f"Client-side redirect detected via {cause}", details

        return False, "", {}

    async def process_link(self, link: str, headers: dict, cookies: dict, idx: int, total: int):
        """
        Process a single link:
        - If skipping due to extension, print a skip message.
        - Otherwise, request it:
          * If non-200, report as protected.
          * If 200 and HTML/text, check for client-side redirects.
        """
        if self.should_skip_url(link):
            if self.verbose:
                print(colored(f"Skipping {idx}/{total}: {link} (static resource)", "blue"), flush=True)
            return

        if self.verbose:
            print(colored(f"Processing {idx}/{total}: {link}", "blue"), flush=True)

        async with self.session.get(link, allow_redirects=False) as resp:
            if resp.status != 200:
                # Non-200 means likely protected
                await self.report_protected_resource(link, f"Non-200 status: {resp.status}", resp)
            else:
                # Attempt to check for client-side redirects if HTML/text
                content_type = resp.headers.get('Content-Type', '').lower()

                if 'html' in content_type or 'text' in content_type:
                    try:
                        text = await resp.text()
                        found_redirect, cause, details = self.detect_client_side_redirect(text)
                        if found_redirect:
                            await self.report_protected_resource(link, cause, resp, redirect_details=details)
                    except UnicodeDecodeError:
                        if self.verbose:
                            print(colored(f"Warning: Unable to decode response for {link} as text. Skipping client-side redirect check.", "yellow"), flush=True)

    async def make_request(self, headers: dict, cookies: dict):
        """
        Process all selected links sequentially for immediate feedback.
        """
        total = len(self.links)
        for i, link in enumerate(self.links, start=1):
            await self.process_link(link, headers, cookies, i, total)

    async def run(self):
        # Load HAR data
        await self.load_har_file()

        # Prepare session
        self.session = aiohttp.ClientSession()

        # Extract links
        all_links = await self.extract_links_from_har()
        if not all_links:
            print(colored('No links found under the given base URL.', 'red', attrs=['bold']), flush=True)
            await self.session.close()
            return

        # Domain selection
        domains = self.get_unique_domains(all_links)
        chosen_domains = self.prompt_domain_selection(domains)

        # Filter links by chosen domains
        filtered_links = []
        for link in all_links:
            parsed = urlparse(link)
            if parsed.netloc in chosen_domains:
                filtered_links.append(link)

        if not filtered_links:
            print(colored("No links found for the selected domains. Exiting.", "red", attrs=["bold"]), flush=True)
            await self.session.close()
            return

        self.links = filtered_links

        # Headers/Cookies from HAR
        headers, cookies = await self.get_headers_and_cookies_from_har()
        if not headers and not cookies:
            if self.verbose:
                print(colored('No headers or cookies found in HAR. Continuing without them.', 'yellow', attrs=['bold']), flush=True)

        # Make requests
        await self.make_request(headers, cookies)
        await self.session.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="A robust crawler that detects protected resources and client-side redirects from a HAR file."
    )
    parser.add_argument("--base-url", required=True, help="The base URL of the application (e.g., https://dev.example.com)")
    parser.add_argument("--har-file", required=True, help="The HAR file to parse and extract URLs from.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output (print all details). Otherwise, only method and URL of protected resources are shown.")
    parser.add_argument("--test-all-extensions", action="store_true", help="Test all URLs regardless of extension")

    args = parser.parse_args()
    base_url = args.base_url
    har_file = args.har_file

    crawler = Crawler(base_url, har_file, args.verbose, args.test_all_extensions)
    asyncio.run(crawler.run())
