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
❯ python3 csaver.py --base-url https://brokencrystals.com --har brokencrystals.har
Protected resource found: https://brokencrystals.com/api/users/one/admin/photo
Protected resource found: https://brokencrystals.com/api/metadata
Protected resource found: https://brokencrystals.com/api/render
Protected resource found: https://brokencrystals.com/api/users/one/admin/adminpermission
Protected resource found: https://brokencrystals.com/api/users/one/admin/adminpermission
```

![image](https://user-images.githubusercontent.com/85877103/212353946-b686d54e-89b7-4a6b-93c4-c1b696bf9d9f.png)


## 🏆 Contributors

- [Dor Shaer](https://github.com/DorShaer) - creator and maintainer
