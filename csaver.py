import asyncio
import json
from typing import Dict, List
import aiohttp
import argparse
from termcolor import colored

class Crawler:
    def __init__(self, base_url: str, interesting_paths: list[str], har_file: str):
        self.base_url = base_url
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
            for domain in domains:
                print(domain)
            user_choice = input(colored("\nDo you want to include specific domains in the test? (y/n): ", 'yellow', attrs=['bold'])).lower()
            if user_choice == 'y':
                domains_to_test = input(colored("Which domains do you want to include in the test? (comma separated): ",'yellow', attrs=['bold'])).lower()
                domains_to_test = domains_to_test.split(',')
                for domain in domains_to_test:
                    for entry in har_data['log']['entries']:
                        request = entry['request']
                        if domain in request['url']:
                            links.append(request['url'])


        return links

    async def process_link(self, link: str, headers: dict):
        #print(f'Making request to: {link}')
        async with self.session.get(link, allow_redirects=False) as resp_without_auth:
            if resp_without_auth.status != 200:
                print(colored('Protected resource found: ', 'green', attrs=['bold']) + colored(f'{link}', 'magenta', attrs=['bold']))

    async def make_request(self, headers: dict):
        tasks = []
        for link in self.links:
            tasks.append(asyncio.create_task(self.process_link(link, headers)))
        await asyncio.gather(*tasks)


    async def run(self):
        self.session = aiohttp.ClientSession()
        links = await self.extract_links_from_har()
        self.links = links
        if not links:
            print(colored('No links found, try to look for any subdomain or api endpoint.', 'red', attrs=['bold']))
            await self.session.close()
            return
        auth_headers = await self.get_headers_and_cookies_from_har()
        if not auth_headers:
            print(colored('No headers found', 'red', attrs=['bold']))
            await self.session.close()
            return   
        await self.make_request(auth_headers)
        await self.session.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True, 
                        help="The base URL of the application")
    parser.add_argument("--har-file", required=True, 
                        help="The har file to extract URLs and auth headers from")
    args = parser.parse_args()
    base_url = args.base_url
    interesting_paths = "/"
    har_file = args.har_file
    crawler = Crawler(base_url, interesting_paths, har_file)
    asyncio.run(crawler.run())
