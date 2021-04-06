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

api_id = 54245
api_hash = "452452452"
session = "NameOfSession"

client = TelegramClient(session, api_id, api_hash)
client.start()


def main():
    # while True:
    #    print("Scan...")
    #    now = datetime.now()
    #    print("start at: ", now)
    check_ip()
    time.sleep(3)

    # print("timer dosent not start")


# 'x-apikey': 'dfghfghdfg',
def check_ip():
    headers = {
        'x-apikey': 'hfghdgfh',
    }

    lastmsg = client.get_messages('shodanresponse_bot', 300)
    ip_addr_for_vtotal = []
    for i in lastmsg:
        ip_addr_list = re.findall("\d+.\d+.\d+.\d+", i.text)
        time.sleep(0.1)
        ip_addr_for_vtotal.append(ip_addr_list[0])

    for now in ip_addr_for_vtotal:
        with open("scannedips200.txt") as f:
            # now = ip_addr_for_vtotal
            if now in f.read():
                print(f"IP arleady in file.({now})")
                # return None
                pass
            else:
                with open("scannedips200.txt", "a") as ad:
                    ad.write(now + '\n')

        ip = now
        # delay
        time.sleep(2)
        r = requests.get('https://www.virustotal.com/api/v3/search?query=' + ip, headers=headers)  # curl get запрос
        json_data = r.json()  # делает вместо кода респонса,жсон ответ

        result_json = json.dumps(json_data, indent=5)  # делает норм вид жсона, чисто для вида
        tmp_arr = []
        root = json_data['data'][0]['attributes']
        # root['last_analysis_stats'][i] in for == harmless, malicious ...
        if root['last_analysis_stats']['malicious'] != 0:
            print("malicious:" + str(root['last_analysis_stats']['malicious']))
            # delay
            time.sleep(2)
            prntres(json_data, ip)
        if root['last_analysis_stats']['suspicious'] != 0:
            # delay
            time.sleep(2)
            print("suspicious:" + str(root['last_analysis_stats']['suspicious']))
            prntres(json_data, ip)
        else:
            pass


def prntres(json_d, ip):
    tmp_arr = []
    repoort = []
    root = json_d['data'][0]['attributes']

    #PREPARING REPORT (HARMLESS ETC.)
    for i in root['last_analysis_stats']:
        if root['last_analysis_stats'][i] != 0:
            tmp = i + ":" + str(root['last_analysis_stats'][i])
            tmp_arr.append(tmp)
    #ПАРСИНГ ОТВЕТА ОТ ВИРУСТОТАЛА, ВЫДЕРГЫВАЕТСЯ НЕ КЛИЗ АНТИВИРУСЫ
    for i in root['last_analysis_results']:
        if str(root['last_analysis_results'][i]['result']) == "clean":
            print("Undetected!")
        else:
            print("Detected!!")
            Engine_name = "**" + root['last_analysis_results'][i]["engine_name"] + "**" + "\n"
            repoort.append(Engine_name)
            Result = "Result: " + root['last_analysis_results'][i]['result'] + "\n \n"
            repoort.append(Result)



    #FORMATING AV DETAILS TO STR FOR SENDING TO TELEGRAM
    str1 = ""
    arr = tmp_arr

    for i in repoort:
        str1 += i

    #PREPARING
    try:
        report1 = arr[0] + '\n' + arr[1] + '\n' + arr[2]
    except IndexError:
        print("first eRrOR")
        try:
            report1 = arr[0] + '\n' + arr[1]
        except IndexError:
            print("second eRrOR")
            report1 = arr[0]

    # DATA
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")


    # SEND FULL NUDES

    send_IP = "**" + ip + "**"                                                                                          #BOLD TEXT IP

    client.send_message("https://t.me/virtot", "IP" + ip + "\n \n " + report1 + "\n " + "AV Details: \n" + "\n" + str1)

    # client.send_message("https://t.me/virtot", dt_string + "\n \n" +"IP address: \n"+ send_IP + ": \n\n" +"Result: \n" + report1 + "\n")
    print("Scan done! Check Public")

    """#########################################################################################################"""
    """#############################################START#######################################################"""
    """#########################################################################################################"""

    main()
