# IP Reputation Checker

A simple python script to check the reputation of an IP address against multiple OSINT tools.

### Currently Supported OSINT Tools: 
* [Shodan](https://www.shodan.io/)
* [AbuseIPDB](https://www.abuseipdb.com/)
* [VirusTotal](https://www.virustotal.com/)

### Requirements
* shodan
* termcolor
* requests

### Installation
1. Clone this repository with the command: 
```
git clone https://github.com/d4rkflam1ngo/ip-reputation-checker && cd ip-reputation-checker
```
3. Install the requirements for the script by running:
```
pip install -r requirements.txt
```
5. Open the file inside a text editor and replace "YOUR_API_KEY" with your relevant API keys
6. Run the script using:
```
python3 reputation.py <IP>
```

### Examples
| Command | Description |
| ----------- | ----------- |
| `python3 reputation.py 142.250.179.238`| Check the reputation of the IP "142.250.179.238" |

### Requested Features
- [x] Add howto to README.md
- [ ] Environment vars (API Keys)
- [ ] Web interface
- [ ] More OSINT tools
