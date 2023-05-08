## 🔥 What is Csaver?

csaver tool is designed to find a protected resouce when creating an authentication object in Bright's platform!

## 📦 Installation

1. [Install Python](https://wiki.python.org/moin/BeginnersGuide/Download)
2. `git clone` this repo
3. `cd` into the repo
4. `pip install -r requirements.txt`

## 💡 Usage

The `csaver` tool takes 2 arguments:

1. `--har` - the location of the HAR file to extarct links from

`python3 csaver --har brokencrystals.har`

```bash
❯ python3 csaver.py --har-file broken.har

Detected domains while parsing the file: 
1. fonts.gstatic.com
2. maps.gstatic.com
3. fonts.googleapis.com
4. www.google.com
5. maps.googleapis.com
6. brokencrystals.com
Which domains do you want to include in the test? (comma separated numbers): 6
Protected resource found: GET https://brokencrystals.com/api/users/one/admin/adminpermission
Original Request Headers: {'Host': 'brokencrystals.com', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0', 'Accept': 'application/json, text/plain, */*', 'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate, br', 'authorization': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE2ODM1NjYwNjh9.cKBocOvqYXgqmiH2V1AvtbNIuOFdy7LM36fRu5IHOs5w0xCbLAorLSbU09ix5VDcdJbeaGaI6JWsypRoYfjyqOvPjlVqQRx-gH2wQi1x8LElGnAzgxBP6vTbuyLFHjWnO2pPbyV13Ry5Nh3levMgivWgUhkOl08BeHyja8Yp4cDypPE4Qatf8u879kntB7O51VTpo6sbkIyrAq3yVnwUaRKjTmzx5f4TEAigLTfBhCBUgMjHwHiRm4zVQI5WwcKTKCC7JlU8f9fKbMHgdLJJ5CTfB-b8sgvtEs8spU3FB9Fg22F9atatglwVXUylrjCWwyJY8wH4pBwrGPduSo8-UedovajfRQgNptIf2UGrK9N3Jh3saclJ2LjP7l2BIACeJkpn-UweE2tfUyke8Ea1TkxHfyPd-GfqYhEguLP5Bbsbgl6cidYvz6AMMDCkOtZhCDZlmHzYAodzI2NobnRu0mXp7t9Oz62g0YUknkK5RqMfJQu4NenNkZTjictkS6pvnf60oRT5Ci-1lb1e9WNFShwONAzORhC54t-1TvjrP_J2Wlu76z1mDIdH2Z9Q2-JHRq2J3Ixhn1fbhqS-0e2bLV8DoDkz4bjmB5ablJN5shjbhUBoafHhzUoWdRcAm-mraBOlo4r0TAiWtgiyTOncjTXRf8k1pwZliScLh_WOQLw', 'Connection': 'keep-alive', 'Referer': 'https://brokencrystals.com/', 'Cookie': 'bc-calls-counter=1683565978774; bc-calls-counter=1683565978117; bc-calls-counter=1683565978118; bc-calls-counter=1683565978880; connect.sid=cLnH1QkdBni-y9xo7vwtBE28bnWnJH4J.u%2FVso4eqaEvw38UQwaMDdHtbBRebjpdKMSeMDm%2F4Pcw', 'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-origin', 'Pragma': 'no-cache', 'Cache-Control': 'no-cache', 'TE': 'trailers'}
Info: Use status code 403 as the reauthentication trigger

```

![image](https://user-images.githubusercontent.com/85877103/236902840-2d86f0f6-5326-4bd1-ab78-12122b525493.png)


## 🏆 Contributors

- [Dor Shaer](https://github.com/DorShaer) - creator and maintainer
