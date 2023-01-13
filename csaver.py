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
        for entry in har_data['log']['entries']:
            request = entry['request']
            if request['url'].startswith(self.base_url):
                for interesting_path in self.interesting_paths:
                    if interesting_path in request['url']:
                        links.append(request['url'])
                        break
        return links

    async def process_link(self, link: str, headers: dict):
        #print(f'Making request to: {link}')
        async with self.session.get(link, allow_redirects=False) as resp_without_auth:
            # if resp_without_auth.status == 200:
            #     print(f'Request to {link} returned {resp_without_auth.status}')
            # else:
            #     print(f'Request to {link} failed with status code: {resp_without_auth.status}')
            if resp_without_auth.status != 200:
                print(colored(f'Protected resource found: {link}', 'green', attrs=['bold']))
                # print(f'Headers: {headers}')
                # print(f'Cookies: {resp_without_auth.cookies}')
                
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
            print(colored('No links found', 'red', attrs=['bold']))
            return
        auth_headers = await self.get_headers_and_cookies_from_har()
        if not auth_headers:
            print(colored('No headers found' 'red', attrs=['bold']))
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
