import os
import json
from radius_functions import *
from datetime import datetime
from time import sleep
from add_logs import add_log
while True:
    try:
        from influxdb import InfluxDBClient
        from dateutil.parser import parse
        break
    except:
        add_log("Install influxdb lib")
        os.system("pip install influxdb")
        add_log("Install dateutil lib")
        os.system("pip install python-dateutil")
with open("config.json", 'r') as file:
    config = json.load(file)
    IMPORT_OLD = config['IMPORT_OLD']
    USERADIUSTIME = config['USERADIUSTIME']
    PATH = config['PATH']
    DBNAME = config['DBNAME']
    DBIP = config['DBIP']
    DBPORT = config['DBPORT']
    DBUSER = config['DBUSER']
    DBPASS = config['DBPASS']
    ONLYNEWDATA = config['ONLYNEWDATA']
    DAILYLOGS = config['DAILYLOGS']
requests = {}
if not os.path.isfile('lasttime.txt'):
    with open('lasttime.txt', 'w') as fp:
        fp.write(str(0))


def saveLastTime(time):
    add_log(f"Save lasttime {time}")
    with open('lasttime.txt','w') as fp:
        fp.write(str(time))


def sendToDB(data, time = False):
    add_log(f"Send to DB: {data}")
    if DBUSER == "" or DBPASS == "":
        socket = InfluxDBClient(host = DBIP, port = DBPORT, database = DBNAME)
    else:
        socket = InfluxDBClient(host = DBIP, port = DBPORT, username = DBUSER, password = DBPASS, database = DBNAME)
    try:
        socket.create_database('radius')
    except:
        pass
    if USERADIUSTIME:
        data += f" {time}"
    socket.switch_database('radius')
    status = socket.write_points(data, database='radius', protocol='line')
    add_log(f"Socket status: {status}")
    socket.close()


def sanatizeStringForInflux(string:str):
    string = string.strip()
    string = string.replace(',','\\,')
    string = string.replace(' ','\\ ')
    string = string.replace('=','\\=')
    return string


def follow(forcedate = False):
    if not forcedate:
        if DAILYLOGS:
            datestring = datetime.now().strftime("%Y%m")[2:]
        else:
            datestring = datetime.now().strftime("%Y%m%d")[2:]
        logfile = PATH + str(datestring) + '.log'
    else:
        datestring = forcedate
        logfile = PATH + str(datestring) + '.log'


    if ONLYNEWDATA:
        with open("lasttime.txt", "r") as fp:
            lasttime = int(fp.read())

    size = 0
    while True:

        currentSize = os.path.getsize(logfile)
        add_log(f"Current size: {round(currentSize / 1024 / 1024, 4)} mb")
        if size == currentSize:
            if IMPORT_OLD:
                print("[done]")
                return
            sleep(1)
            continue



        if forcedate:
            if DAILYLOGS:
                datestring = datetime.now().strftime("%Y%m")[2:]
            else:
                datestring = datetime.now().strftime("%Y%m%d")[2:]
            logfile = PATH + str(datestring) + '.log'
        add_log(f"Open log file: {logfile}")
        fh = open(logfile, "r")
        d = ""
        i = 0
        for d in fh:
            d = d.replace("\n", "")
            i = 1
            d = d.strip()
            a = d.split(",")
            server = a[0].replace('"', '')
            date = a[2].replace('"', '')
            time = a[3].replace('"', '')
            timestamp = int(parse(date + " " + time).timestamp())

            if ONLYNEWDATA and timestamp < lasttime:
                continue
            saveLastTime(timestamp)
            try:
                stype = int(a[4].replace('"', ""))
            except:
                stype = a[4].replace('"', "")
            add_log(f"Stype: {stype}")
            client = a[5].replace('"', "")
            origin = a[6].replace('"', "")
            client_mac = a[8].replace('-', ':').replace('"', '').strip()
            if client_mac and not client_mac.count(":"):
                tmp_client_mac = client_mac
                client_mac = ""
                u = 0
                for i in tmp_client_mac:
                    client_mac += i
                    u += 1
                    if u == 2:
                        u = 0
                        client_mac += ":"
            ap_host = a[11].replace('"', '')
            ap_ip = a[15].replace('"', '')
            ap_radname = a[16][0:5].replace('"', '').lower()
            ap_radname_full = sanatizeStringForInflux(a[16]).replace('"', '').lower()
            speed = a[20].replace('"', '')
            policy = a[60].replace('"', "")
            auth = a[23].replace('"', "")
            policy2 = a[24].replace('"', "")
            reason = a[25].replace('"', "")
            rs = translateReason(reason)
            tt = translatePackageType(stype)
            add_log(f"Stype relog: {tt}")
            tq = int(timestamp / 900) * 900
            if origin.count('\\'):
                ab = origin.split('\\')
            elif origin.count('/'):
                ab = origin.split('/')
            else:
                continue
            if type(ab) == list:
                if len(ab) == 4:
                    origin_client = ab[3]
                    OU = ab[2]
                elif len(ab) == 3:
                    origin_client = ab[2]
                    OU = ab[1]
                elif len(ab) == 2:
                    origin_client = ab[1]
                    OU = ab[0]
                else:
                    origin_client = origin
            else:
                origin_client = origin
            influxtime = timestamp * 1000000000
            OU = sanatizeStringForInflux(str(OU))
            origin_client = sanatizeStringForInflux(str(origin_client))
            while True:
                if stype == 1:
                    add_log("Requesting Access")
                    if not str(origin_client) + str(ap_radname_full) in requests or requests[str(origin_client) + str(ap_radname_full)] == timestamp:
                        stype = 2
                        continue
                    s = speed.split(" ")
                    speed = s[1]
                    if not client_mac:
                        client_mac = "0"
                    if not ap_radname_full:
                        ap_radname_full = "0"
                    if not origin_client:
                        origin_client = "0"
                    sendToDB(f"{DBNAME},type=request,ap={ap_radname_full},special={client_mac},special_type=mac value=\"{origin_client}\",special=\"{client_mac}\"", influxtime)
                    break
                elif stype == 2:
                    add_log("Accepted")
                    if not client_mac:
                        client_mac = "0"
                    if not ap_radname_full:
                        ap_radname_full = "0"
                    if not origin_client:
                        origin_client = "0"
                    sendToDB(f"{DBNAME},type=accept,ap={ap_radname_full},special={client_mac},special_type=mac value=\"{origin_client}\",special=\"{client_mac}\"", influxtime)
                    break
                elif stype == 3:
                    add_log("Rejected")
                    if not ap_radname_full:
                        ap_radname_full = "0"
                    if not reason:
                        reason = "0"
                    if not origin_client:
                        origin_client = "0"
                    if not rs:
                        rs = "0"
                    sendToDB(f"{DBNAME},type=rejected,ap={ap_radname_full},special={reason},special_type=reason value=\"{origin_client}\",special_val=\"{rs}\"", influxtime)
                    break
                elif stype == 4:
                    add_log("Accounting-Request")
                    break
                elif stype == 5:
                    add_log("Accounting-Response")
                    break
                elif stype == 11:
                    add_log("Access-Challenge")
                    break
                else:
                    add_log(f"Cannot add this radius: {reason}\t{origin_client}\t{timestamp}\t{client}\t{tt}\t{ap_radname_full}\n")
                    break
        add_log(f"Successfully added {datestring}")

        out = []
        fh.close()
        size = currentSize
        break
while True:
    lastsize = -1
    if not IMPORT_OLD:
        if DAILYLOGS:
            datestring = datetime.now().strftime("%Y%m")[2:]
        else:
            datestring = datetime.now().strftime("%Y%m%d")[2:]
        logfile = PATH + str(datestring) + '.log'
        size_now = os.path.getsize(logfile)
        if size_now != lastsize:
            follow(forcedate = False)
            lastsize = size_now
    else:
        for year in range(10, 16):
            for i in range(1, 13):
                if i < 10:
                    month = "0" + str(i)
                else:
                    month = str(i)
                datestring = str(year) + str(month)
                logfile = PATH + str(datestring) + '.log'
                if size_now != lastsize:
                    follow(forcedate = str(year) + str(month))
                    lastsize = size_now
    sleep(60)


