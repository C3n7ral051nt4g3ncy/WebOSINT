<div align="center">
 
<img src="https://img.shields.io/badge/Python-purple?style=for-the-badge&logo=python&logoColor=white"/> 
<a href="https://github.com/C3n7ral051nt4g3ncy"> <img alt="GitHub" src="https://img.shields.io/badge/GitHub-purple?style=for-the-badge&logo=github&logoColor=white"/>
<a href="https://ko-fi.com/tacticalintelanalyst"> <img alt="Kofi" src="https://img.shields.io/badge/Ko--fi-purple?style=for-the-badge&logo=ko-fi&logoColor=white">
<a href="https://user-images.githubusercontent.com/104733166/171052611-1f76b07c-832f-4a4a-9a0a-2f94595c28c9.png"/><img alt="BTC" src="https://img.shields.io/badge/Bitcoin-purple?style=for-the-badge&logo=bitcoin&logoColor=white">

<br>
<br>
  
<a href="https://github.com/C3n7ral051nt4g3ncy/webosint/blob/master/LICENSE"/> <img alt="Licence" src="https://img.shields.io/badge/LICENCE-MIT-purple">
  
</div>
  
<br>

<p align="center"> <img width="658" src="https://user-images.githubusercontent.com/104733166/178506130-02e6ebf5-2f81-4722-826b-3969b3da4e46.png"> <p/>

<br>
<br>
<br>


# W3b0s1nt 🌐
**W3b0s1nt** is a Python script to gain intelligence on a domain.

<br>

  
# Requirements 🐍
- [Python 3](https://www.python.org/downloads/)
- Don't forget to install the requirements.txt
- You will be limited in your search requests with the Hacker Target free API, you can purchase a Hacker Target membership and your API here: (https://hackertarget.com/scan-membership/)
- For the WhoisXML API; this is an easy process and free, simply create an account and use the trial 50 free API requests:(https://whois.whoisxmlapi.com)

<br>

# Installation ⚙️

```
git clone https://github.com/C3n7ral051nt4g3ncy/webosint
```
  
```
cd webosint
```
 
```
pip3 install -r requirements.txt
```
  
```
python3 webosint.py
```
<br>

Once the script starts, you have hardly any typing to do:
``` 
- Domain format example: google.com
- To choose between yes and no: Type Y or y for Yes  |  N or n for No
- Choose between a free search and search with your API Key: Type -F or f for the free search | Type -API or api for the search with your API keys
```  


<br>

# API Keys 🔑
In the `Config.json` file, just paste your API Keys inside the quotation marks `"API Key"` (see photo below)
- It's **not an obligation** to pay for a Hacker Target API key, you can leave it how it is, just choose the free search by typing **-F** each time the tool asks you to choose between the Free search and the search using your API key.
- It's an **obligation** ✅ however to get yourself a WhoisXML Api key, this is free (50 searches each month), just go to the WhoisXML website and get an account to get your API key: (https://whois.whoisxmlapi.com)
<br>

<p align="center">
  <img width="490" height="320" src="https://user-images.githubusercontent.com/104733166/178601842-4945f6eb-b628-4c29-b890-01ba1c47fb69.png">
</p>


<br>
<br>
  
# Tool Sequence ⛓️

### [1]
``` 
Checking the domain is registered
```
### [2]
``` 
Get the domain ip address and location data, Version, ASN
```
### [3]
``` 
Reverse ip search to extract all domains with the same ip (HackerTarget free and paid API)
``` 
### [4]
``` 
DNS records with HackerTarget free and Paid API 
```  
### [5]
``` 
Whois domain information
```   
### [6]
``` 
Domain reputation check with WhoisXML free API
```   

<br>

# Potential Issues and Errors ❌
Before making this repository public, I gave private access to a few people, some were getting an error right at the beginning of the script and websites that were `Registered` were being shown as `Not Registered`. Found the problem/issue, some people have both `whois` and  `python-whois` modules, and they were conflicting with each other. Fixing the issue will be:
``` 
pip3 uninstall whois
```   
``` 
pip3 uninstall python-whois
``` 
Make a clean install: 
``` 
pip 3 install python-whois
```   

<br>
  
Or simply use `virtualenv` 🧠

<br>

# Disclaimer ⚠️

`This tool is for the OSINT and Cyber community, don't use it for wrong, immoral, or illegal reasons.`

<br>

# Tool Improvements 🔧
Feel free to contribute and to change some code within the tool, submit a PR (Pull Request), or submit your thoughts here on github in the [Webosint discussions](https://github.com/C3n7ral051nt4g3ncy/webosint/discussions)
<br>
<br>

# License ⚖️
[MIT](https://choosealicense.com/licenses/mit/)
 
<br>
  
# Support 💜
If you like this simple Python tool, feel free to donate to my work by clicking on the **KO-FI** Badge or the **BITCOIN** Badge at the top of this .readme file, you can also scan directly the BTC QR Code to get my BTC Address. 

<br>

# Mention 🔊
Thank you to [Hacker Target](https://hackertarget.com) for their API and great work which makes this tool possible, thank you also to [WHOisXML](https://main.whoisxmlapi.com) for their API as they make a free API (50 searches per month) which provides a great opportunity for so many people in the Cyber community.
  
<br>
  
<p align="center"><img width="433" height="233" src="https://user-images.githubusercontent.com/104733166/178512035-bb81cafc-f785-4426-9268-6634d3c2152d.png"></p>

<br>
  
 <p align="center"><img width="933" height="166" src="https://user-images.githubusercontent.com/104733166/178512622-949c845e-6170-4994-ac5b-d3eaeb2cbd4b.png"></p>


