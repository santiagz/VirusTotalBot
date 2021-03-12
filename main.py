import json

abc = """{    "Botvrij.eu": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Botvrij.eu"
                         },
                         "CMC Threat Intelligence": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "CMC Threat Intelligence"
                         },
                         "Snort IP sample list": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Snort IP sample list"
                         },
                         "VX Vault": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "VX Vault"
                         },
                         "Armis": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Armis"
                         },
                         "Comodo Valkyrie Verdict": {
                              "category": "undetected",
                              "result": "unrated",
                              "method": "blacklist",
                              "engine_name": "Comodo Valkyrie Verdict"
                         },
                         "PhishLabs": {
                              "category": "undetected",
                              "result": "unrated",
                              "method": "blacklist",
                              "engine_name": "PhishLabs"
                         },
                         "K7AntiVirus": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "K7AntiVirus"
                         },
                         "CINS Army": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "CINS Army"
                         },
                         "Cyren": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Cyren"
                         },
                         "Quttera": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Quttera"
                         },
                         "BlockList": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "BlockList"
                         },
                         "OpenPhish": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "OpenPhish"
                         },
                         "Feodo Tracker": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Feodo Tracker"
                         },
                         "Web Security Guard": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Web Security Guard"
                         },
                         "Scantitan": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Scantitan"
                         },
                         "AlienVault": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "AlienVault"
                         },
                         "Sophos": {
                              "category": "undetected",
                              "result": "unrated",
                              "method": "blacklist",
                              "engine_name": "Sophos"
                         },
                         "Phishtank": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Phishtank"
                         },
                         "EonScope": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "EonScope"
                         },
                         "Cyan": {
                              "category": "undetected",
                              "result": "unrated",
                              "method": "blacklist",
                              "engine_name": "Cyan"
                         },
                         "Spam404": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Spam404"
                         },
                         "SecureBrain": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "SecureBrain"
                         },
                         "Hoplite Industries": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Hoplite Industries"
                         },
                         "CRDF": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "CRDF"
                         },
                         "Rising": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Rising"
                         },
                         "StopForumSpam": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "StopForumSpam"
                         },
                         "Fortinet": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Fortinet"
                         },
                         "alphaMountain.ai": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "alphaMountain.ai"
                         },
                         "Netcraft": {
                              "category": "malicious",
                              "result": "malicious",
                              "method": "blacklist",
                              "engine_name": "Netcraft"
                         },
                         "Virusdie External Site Scan": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Virusdie External Site Scan"
                         },
                         "Artists Against 419": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Artists Against 419"
                         },
                         "SCUMWARE.org": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "SCUMWARE.org"
                         },
                         "Google Safebrowsing": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Google Safebrowsing"
                         },
                         "ADMINUSLabs": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ADMINUSLabs"
                         },
                         "CyberCrime": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "CyberCrime"
                         },
                         "AutoShun": {
                              "category": "undetected",
                              "result": "unrated",
                              "method": "blacklist",
                              "engine_name": "AutoShun"
                         },
                         "Trustwave": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Trustwave"
                         },
                         "AICC (MONITORAPP)": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "AICC (MONITORAPP)"
                         },
                         "CyRadar": {
                              "category": "malicious",
                              "result": "malicious",
                              "method": "blacklist",
                              "engine_name": "CyRadar"
                         },
                         "Dr.Web": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Dr.Web"
                         },
                         "Emsisoft": {
                              "category": "malicious",
                              "result": "phishing",
                              "method": "blacklist",
                              "engine_name": "Emsisoft"
                         },
                         "Malc0de Database": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Malc0de Database"
                         },
                         "Avira": {
                              "category": "malicious",
                              "result": "phishing",
                              "method": "blacklist",
                              "engine_name": "Avira"
                         },
                         "securolytics": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "securolytics"
                         },
                         "Antiy-AVL": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Antiy-AVL"
                         },
                         "Yandex Safebrowsing": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Yandex Safebrowsing"
                         },
                         "Quick Heal": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Quick Heal"
                         },
                         "ESTsecurity-Threat Inside": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ESTsecurity-Threat Inside"
                         },
                         "CLEAN MX": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "CLEAN MX"
                         },
                         "DNS8": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "DNS8"
                         },
                         "benkow.cc": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "benkow.cc"
                         },
                         "EmergingThreats": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "EmergingThreats"
                         },
                         "AegisLab WebGuard": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "AegisLab WebGuard"
                         },
                         "MalwareDomainList": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "MalwareDomainList"
                         },
                         "Lumu": {
                              "category": "undetected",
                              "result": "unrated",
                              "method": "blacklist",
                              "engine_name": "Lumu"
                         },
                         "Kaspersky": {
                              "category": "undetected",
                              "result": "unrated",
                              "method": "blacklist",
                              "engine_name": "Kaspersky"
                         },
                         "Segasec": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Segasec"
                         },
                         "Malware Domain Blocklist": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Malware Domain Blocklist"
                         },
                         "desenmascara.me": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "desenmascara.me"
                         },
                         "URLhaus": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "URLhaus"
                         },
                         "PREBYTES": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "PREBYTES"
                         },
                         "Sucuri SiteCheck": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Sucuri SiteCheck"
                         },
                         "Blueliv": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Blueliv"
                         },
                         "ZCloudsec": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ZCloudsec"
                         },
                         "ZeroCERT": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ZeroCERT"
                         },
                         "Phishing Database": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Phishing Database"
                         },
                         "zvelo": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "zvelo"
                         },
                         "MalwarePatrol": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "MalwarePatrol"
                         },
                         "MalBeacon": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "MalBeacon"
                         },
                         "Sangfor": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Sangfor"
                         },
                         "IPsum": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "IPsum"
                         },
                         "Spamhaus": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Spamhaus"
                         },
                         "Malwared": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Malwared"
                         },
                         "BitDefender": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "BitDefender"
                         },
                         "GreenSnow": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "GreenSnow"
                         },
                         "G-Data": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "G-Data"
                         },
                         "StopBadware": {
                              "category": "undetected",
                              "result": "unrated",
                              "method": "blacklist",
                              "engine_name": "StopBadware"
                         },
                         "Malwarebytes hpHosts": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Malwarebytes hpHosts"
                         },
                         "malwares.com URL checker": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "malwares.com URL checker"
                         },
                         "NotMining": {
                              "category": "undetected",
                              "result": "unrated",
                              "method": "blacklist",
                              "engine_name": "NotMining"
                         },
                         "Forcepoint ThreatSeeker": {
                              "category": "undetected",
                              "result": "unrated",
                              "method": "blacklist",
                              "engine_name": "Forcepoint ThreatSeeker"
                         },
                         "Certego": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Certego"
                         },
                         "ESET": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ESET"
                         },
                         "Threatsourcing": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Threatsourcing"
                         },
                         "MalSilo": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "MalSilo"
                         },
                         "Nucleon": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Nucleon"
                         },
                         "BADWARE.INFO": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "BADWARE.INFO"
                         },
                         "ThreatHive": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ThreatHive"
                         },
                         "FraudScore": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "FraudScore"
                         },
                         "Tencent": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Tencent"
                         },
                         "Baidu-International": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Baidu-International"
                         }
                    }"""

dictData = json.loads(abc)

EngineName = 'Engine Name' + ' : ' + dictData["Baidu-International"]["engine_name"]
#print('Engine Name' + ' : ' + dictData["Baidu-International"]["engine_name"])

Categoty = 'Category' + ' : ' + dictData["Baidu-International"]["category"]
#print('Category' + ' : ' + dictData["Baidu-International"]["category"])

Result = 'Result' + ' : ' + dictData["Baidu-International"]["result"]
#print('Result' + ' : ' + dictData["Baidu-International"]["result"])

Method = 'Method' + ' : ' + dictData["Baidu-International"]["method"]
#print('Method' + ' : ' + dictData["Baidu-International"]["method"])




{
                         "CMC Threat Intelligence": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "CMC Threat Intelligence"
                         },
                         "CLEAN MX": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "CLEAN MX"
                         },
                         "DNS8": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "DNS8"
                         },
                         "MalSilo": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "MalSilo"
                         },
                         "Snort IP sample list": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Snort IP sample list"
                         },
                         "AICC (MONITORAPP)": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "AICC (MONITORAPP)"
                         },
                         "benkow.cc": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "benkow.cc"
                         },
                         "VX Vault": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "VX Vault"
                         },
                         "securolytics": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "securolytics"
                         },
                         "MalwarePatrol": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "MalwarePatrol"
                         },
                         "Armis": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Armis"
                         },
                         "MalBeacon": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "MalBeacon"
                         },
                         "Comodo Valkyrie Verdict": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Comodo Valkyrie Verdict"
                         },
                         "PhishLabs": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "PhishLabs"
                         },
                         "EmergingThreats": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "EmergingThreats"
                         },
                         "Forcepoint ThreatSeeker": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Forcepoint ThreatSeeker"
                         },
                         "K7AntiVirus": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "K7AntiVirus"
                         },
                         "Virusdie External Site Scan": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Virusdie External Site Scan"
                         },
                         "CINS Army": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "CINS Army"
                         },
                         "Spamhaus": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Spamhaus"
                         },
                         "Quttera": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Quttera"
                         },
                         "AegisLab WebGuard": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "AegisLab WebGuard"
                         },
                         "MalwareDomainList": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "MalwareDomainList"
                         },
                         "CyberCrime": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "CyberCrime"
                         },
                         "Lumu": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Lumu"
                         },
                         "Google Safebrowsing": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Google Safebrowsing"
                         },
                         "Kaspersky": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Kaspersky"
                         },
                         "BitDefender": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "BitDefender"
                         },
                         "Emsisoft": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Emsisoft"
                         },
                         "GreenSnow": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "GreenSnow"
                         },
                         "Quick Heal": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Quick Heal"
                         },
                         "G-Data": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "G-Data"
                         },
                         "Segasec": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Segasec"
                         },
                         "OpenPhish": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "OpenPhish"
                         },
                         "Malware Domain Blocklist": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Malware Domain Blocklist"
                         },
                         "AutoShun": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "AutoShun"
                         },
                         "Trustwave": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Trustwave"
                         },
                         "Web Security Guard": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Web Security Guard"
                         },
                         "CyRadar": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "CyRadar"
                         },
                         "desenmascara.me": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "desenmascara.me"
                         },
                         "ADMINUSLabs": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ADMINUSLabs"
                         },
                         "Scantitan": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Scantitan"
                         },
                         "IPsum": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "IPsum"
                         },
                         "Dr.Web": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Dr.Web"
                         },
                         "AlienVault": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "AlienVault"
                         },
                         "Sophos": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Sophos"
                         },
                         "malwares.com URL checker": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "malwares.com URL checker"
                         },
                         "Phishtank": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Phishtank"
                         },
                         "EonScope": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "EonScope"
                         },
                         "Malwared": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Malwared"
                         },
                         "Avira": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Avira"
                         },
                         "NotMining": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "NotMining"
                         },
                         "Cyan": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Cyan"
                         },
                         "Antiy-AVL": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Antiy-AVL"
                         },
                         "SCUMWARE.org": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "SCUMWARE.org"
                         },
                         "Spam404": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Spam404"
                         },
                         "ESTsecurity-Threat Inside": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ESTsecurity-Threat Inside"
                         },
                         "Certego": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Certego"
                         },
                         "Yandex Safebrowsing": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Yandex Safebrowsing"
                         },
                         "ESET": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ESET"
                         },
                         "Threatsourcing": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Threatsourcing"
                         },
                         "URLhaus": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "URLhaus"
                         },
                         "SecureBrain": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "SecureBrain"
                         },
                         "Nucleon": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Nucleon"
                         },
                         "PREBYTES": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "PREBYTES"
                         },
                         "Sucuri SiteCheck": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Sucuri SiteCheck"
                         },
                         "Blueliv": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Blueliv"
                         },
                         "Hoplite Industries": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Hoplite Industries"
                         },
                         "Netcraft": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Netcraft"
                         },
                         "CRDF": {
                              "category": "malicious",
                              "result": "malicious",
                              "method": "blacklist",
                              "engine_name": "CRDF"
                         },
                         "ThreatHive": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ThreatHive"
                         },
                         "BADWARE.INFO": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "BADWARE.INFO"
                         },
                         "FraudScore": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "FraudScore"
                         },
                         "Fortinet": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Fortinet"
                         },
                         "Tencent": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Tencent"
                         },
                         "StopBadware": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "StopBadware"
                         },
                         "StopForumSpam": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "StopForumSpam"
                         },
                         "zvelo": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "zvelo"
                         },
                         "ZeroCERT": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "ZeroCERT"
                         },
                         "Baidu-International": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Baidu-International"
                         },
                         "Phishing Database": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "Phishing Database"
                         },
                         "alphaMountain.ai": {
                              "category": "harmless",
                              "result": "clean",
                              "method": "blacklist",
                              "engine_name": "alphaMountain.ai"
                         }
                    }