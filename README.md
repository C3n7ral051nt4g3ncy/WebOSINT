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

<div align="center">
<img width="633" src="https://user-images.githubusercontent.com/104733166/185790639-b1f09747-aea3-4f64-a52f-d70efd820a22.png"></div>


<br>
<br>
<br>


# WebOSINT 🌐
**WebOSINT** is a Python script to gather (passive) domain intelligence.

<br>

  
# Requirements 🐍
- [Python 3](https://www.python.org/downloads/)
- Don't forget to install `requirements.txt`
- You will be limited in your search requests with the Hacker Target free API, you can purchase a Hacker Target membership and your API here: (https://hackertarget.com/scan-membership/)
- For the WhoisXML API; this is an easy process and free, simply create an account and use the `trial 500 free API requests`  (Once you have used the 500 requests you will need to make a purchase, and if you don't want a yearly or monthly membership you can make one-time payments, `5000 queries for 100,00$ USD` or `1000 queries for 30,00$ USD`  :(https://whois.whoisxmlapi.com)

<br>

# Running the script with Docker 🐳
```
docker run -it scorpix06/webosint
```


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

Once the script starts, you won't have much typing to do: 
``` 
- Domain format example: google.com
- To choose between yes and no: Type Y or y for Yes  |  N or n for No
- Choose between a free search and search with your API Key: Type -F or f for the free search | Type -API or api for the search with your API keys
```  


<br>

# API Keys 🔑
In the `Config.json` file, just paste your API Keys inside the quotation marks `"API Key"` (see photo below)
- It's **not an obligation** to pay for a **Hacker Target** API key, you can leave it how it is, just choose the free search by typing  `-F` each time the tool asks you to choose between the Free search and the search using your API key.
- It's an **obligation** ✅ to get yourself a **WhoisXML** Api key, this is free (`500 searches free`), just go to the WhoisXML website and get an account to get your API key: (https://whois.whoisxmlapi.com)
- It's also an **obligation** ✅ to get yourself a **WhoisFreaks** Api key, this is free (`100 searches free`), just go to the WhoisFreaks website and sign up to get your API key: (https://whoisfreaks.com), and by the way, once your 100 free searches are used, you can purchase 5000 API Calls for only 19,00$ USD


<br>

  <img width="266" height="180" src="https://user-images.githubusercontent.com/104733166/188323393-f47155f7-f9de-48f0-b90c-15693ddf2447.png">



<br>
<br>
  
# Tool Sequence ⛓️

### [1]
``` 
Checking if the domain is registered
```
### [2]
``` 
Get the domain ip address and location data, Version, ASN (Tool updated 16 July 2022, now with double IP verification)
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
Domain CERT (Certificate) search using CRT.SH
```   

### [7]
``` 
Domain reputation scan with WhoisXML free API
```   

### [8]
``` 
Subdomain Scanner 
```   

### [9]
``` 
Historical Whois Search with WhoisFreaks free API (100 Free API Calls)
```   


<br>

# Terminal Scrollback Buffer 🔣
Be aware that for the reverse IP search using the Hacker Target API, you are going to get a few hundred results for some websites, make sure that your Terminal Scrollback preferences are set to `unlimited scrollback` so that you can scroll back up to see all results!

<p align="center">
<img width="333" src="https://user-images.githubusercontent.com/104733166/179029659-f1591798-d0e9-45d9-8dbb-c7de0a82585f.png"></p>


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
If you like this simple Python tool, feel free to donate to my work by clicking on the **KO-FI** Badge or the **BITCOIN** Badge at the top of this  `README.md` file, you can also scan my BTC QR Code directly to get my BTC Address. 

<br>

# Mention 🔊
Thank you to [Hacker Target](https://hackertarget.com) for their API and great work which makes this tool possible, thank you also to [WHOisXML](https://main.whoisxmlapi.com) for their API as they make a free API (500 searches) which provides a great opportunity for the people in the Cyber community, and thanks to [Whois Freaks](https://whoisfreaks.com)for their free 100 search API Trial.
Thanks to [@cipher387](https://github.com/cipher387)/[@cyb_detective](https://twitter.com/cyb_detective) and to [Euler Neto](https://github.com/netoeuler) for testing the script before release and finding 2 minor corrections.
  
<br>
  
<p align="center"><img width="233" height="133" src="https://user-images.githubusercontent.com/104733166/178512035-bb81cafc-f785-4426-9268-6634d3c2152d.png"></p>

<br>
  
 <p align="center"><img width="433" height="66" src="https://user-images.githubusercontent.com/104733166/178512622-949c845e-6170-4994-ac5b-d3eaeb2cbd4b.png"></p>
 
 <br>
 
 <p align="center"><img width="166" height="133" src="https://user-images.githubusercontent.com/104733166/185790948-bc101640-be75-47d3-b437-9adf4737d3fa.png"></p>
 


