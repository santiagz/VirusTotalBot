from telethon import TelegramClient
import time
from telethon import sync, events
from json2table import convert
import requests
import json
import array
from datetime import datetime
import re
import io

api_id = 3048536
api_hash = "d6b47c422a9818ab4e54241d15a33f09"
session = "VirusTotalBot"

client = TelegramClient(session, api_id, api_hash)
client.start()


def main():
    while True:
        print("Scan...")
        now = datetime.now()
        print("start at: ", now)
        check_ip()
        time.sleep(5)

    # print("timer dosent not start")


def check_ip():
    headers = {
        'x-apikey': '4e48f3628c3f9ccf1ebf44ac714bd71704243a469b00a0e14cfec3e2a65145b3',
    }

    lastmsg = client.get_messages('shodanresponse_bot')
    ip_addr_list = re.findall("\d+.\d+.\d+.\d+", lastmsg[0].text)

    ip_addr_for_vtotal = ip_addr_list[0]

    with open("scannedips.txt") as f:
        now = ip_addr_for_vtotal
        if now in f.read():
            print("IP arleady in file.")
            return None
        else:
            with open("scannedips.txt", "a") as ad:
                ad.write(now + '\n')

    ip = ip_addr_for_vtotal
    r = requests.get('https://www.virustotal.com/api/v3/search?query=' + ip, headers=headers)  # curl get запрос
    json_data = r.json()  # делает вместо кода респонса,жсон ответ

    result_json = json.dumps(json_data, indent=5)  # делает норм вид жсона, чисто для вида
    tmp_arr = []
    root = json_data['data'][0]['attributes']
    #root['last_analysis_stats'][i] in for == harmless, malicious ...
    if root['last_analysis_stats']['malicious'] != 0:
        print("malicious:"+str(root['last_analysis_stats']['malicious']))
        prntres(json_data, ip)
    if root['last_analysis_stats']['suspicious'] != 0:
        print("suspicious:"+str(root['last_analysis_stats']['suspicious']))
        prntres(json_data, ip)
    else:
        pass
    """
    for i in root['last_analysis_stats']:
        print(type(root['last_analysis_stats'][i]))
        #print(root['last_analysis_stats'][i]['malicious'])
        if root['last_analysis_stats']['malicious'] != 0 or root['last_analysis_stats'][i]['suspicious'] != 0:
            tmp = i + ":" + str(root['last_analysis_stats'][i])
            tmp_arr.append(tmp)
        else:
            pass
    print(tmp_arr)



    prntres(json_data, ip)
    """


def prntres(json_d, ip):
    tmp_arr = []
    repoort = []
    root = json_d['data'][0]['attributes']
    for i in root['last_analysis_stats']:
        if root['last_analysis_stats'][i] != 0:
            tmp = i + ":" + str(root['last_analysis_stats'][i])
            tmp_arr.append(tmp)
    for i in root['last_analysis_results']:
        Engine_name = "**" + root['last_analysis_results'][i]["engine_name"] + "**" + "\n"
        repoort.append(Engine_name)

        # Category = "Category: " + root['last_analysis_results'][i]["category"]+"\n"
        # repoort.append(Category)

        Result = "Result: " + root['last_analysis_results'][i]['result'] + "\n \n"
        repoort.append(Result)

    str1 = ""
    for i in repoort:
        str1 += i

    arr = tmp_arr
    try:
        report1 = arr[0] + '\n' + arr[1] + '\n' + arr[2]
    except IndexError:
        report1 = arr[0]
    # SEND FULL NUDES
    #client.send_message("https://t.me/virtot", get_last_msg() + "\n \n" + report1 +"\n"+ "AV Details: \n" + "\n" + str1)

    # SEND SHORT
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    send_IP = "**" + ip + "**"
    client.send_message("https://t.me/virtot", dt_string + "\n \n" +"IP address: \n"+ send_IP + ": \n\n" +"Result: \n" + report1 + "\n")
    print("Scan done! Check Public")


"""#########################################################################################################"""
"""#############################################START#######################################################"""
"""#########################################################################################################"""

main()
