import asyncio
import json
from typing import Dict, List
import aiohttp
import argparse
from termcolor import colored

class Crawler:
    def __init__(self, interesting_paths: list[str], har_file: str):
        self.interesting_paths = interesting_paths
        self.har_file = har_file
        self.session = None
        self.auth_headers = {}

    async def get_headers_and_cookies_from_har(self) -> tuple[Dict[str, str], Dict[str, str]]:
        with open(self.har_file, 'r') as f:
            har_data = json.load(f)

        headers = {}
        cookies = {}
        for entry in har_data['log']['entries']:
            request = entry['request']
            for header in request['headers']:
                headers[header['name']] = header['value']
            for cookie in request.get('cookies', []):
                cookies[cookie['name']] = cookie['value']
        return headers, cookies

    async def extract_links_from_har(self):
        links = []
        with open(self.har_file, 'r') as f:
            har_data = json.load(f)
            domains = set()
            for entry in har_data['log']['entries']:
                request = entry['request']
                domain = request['url'].split("//")[-1].split("/")[0]
                domains.add(domain)
            print(colored("\nDetected domains while parsing the file: ", 'blue', attrs=['bold']))
            domain_mapping = {}
            for idx, domain in enumerate(domains):
                print(f"{idx + 1}. {domain}")
                domain_mapping[idx + 1] = domain
            domains_to_test = input(colored("Which domains do you want to include in the test? (comma separated numbers): ",'yellow', attrs=['bold'])).lower()
            domains_to_test = [int(x.strip()) for x in domains_to_test.split(',')]
            for idx in domains_to_test:
                domain = domain_mapping[idx]
                for entry in har_data['log']['entries']:
                    request = entry['request']
                    if domain in request['url']:
                        post_data = request['postData']['text'] if request['method'] == 'POST' and 'postData' in request else None  # Extract POST data if available
                        request_headers = {header['name']: header['value'] for header in request['headers']}  # Extract request headers
                        links.append((request['url'], request['method'], request_headers, post_data))  # Store the link, request method, request headers, and POST data as a tuple

        return links
    async def process_link(self, link: str, method: str, original_headers: dict, auth_headers: dict, post_data: str = None):
        async with self.session.get(link, headers=auth_headers, allow_redirects=False) as resp_without_auth:
            if resp_without_auth.status != 200:
                response_text = await resp_without_auth.text()
                response_headers = resp_without_auth.headers
                print(colored('Protected resource found: ', 'green', attrs=['bold']) + colored(f'{method} {link}', 'magenta', attrs=['bold']))
                print(colored('Original Request Headers: ', 'yellow', attrs=['bold']) + colored(f'{original_headers}', 'cyan', attrs=['bold']))
                if method == 'POST' and post_data:
                    print(colored('Original POST data: ', 'yellow', attrs=['bold']) + colored(f'{post_data}', 'cyan', attrs=['bold']))

    async def make_request(self, auth_headers: dict):
        tasks = []
        for link, method, original_headers, post_data in self.links:
            tasks.append(asyncio.create_task(self.process_link(link, method, original_headers, auth_headers, post_data)))
        await asyncio.gather(*tasks)

    async def run(self):
        self.session = aiohttp.ClientSession()
        links = await self.extract_links_from_har()
        self.links = links
        if not links:
            print(colored('No links found, try to look for any subdomain or api endpoint.', 'red', attrs=['bold']))
            await self.session.close()
            return
        headers, cookies = await self.get_headers_and_cookies_from_har()
        if not headers:
            print(colored('No headers found', 'red', attrs=['bold']))
            await self.session.close()
            return   
        await self.make_request(headers)
        await self.session.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--har-file", required=True, 
                        help="The har file to extract URLs and auth headers from")
    args = parser.parse_args()
    interesting_paths = "/"
    har_file = args.har_file
    crawler = Crawler(interesting_paths, har_file)
    asyncio.run(crawler.run())
