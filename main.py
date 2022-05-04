#!/bin/python
import sys
import os
import argparse
import json
import socket
import subprocess


def bitestring_to_string(bytestring):
    return bytestring.decode("utf-8")

def validate_ip(addr):
    try:
        socket.inet_aton(addr)
        return True  # legal
    except socket.error:
        return False  # Not legal


def configure():
    global wlan, ppp, IP, Netmask
    # CHECK WHETHER WIFI IS SUPPORTED OR NOT
    print('Verifying connections')
    wlan = ''
    ppp = ''
    p = subprocess.Popen(['iwconfig'], stdout=subprocess.PIPE)
    out, err = p.communicate()
    if out != None and not err:
        lines = bitestring_to_string(out).splitlines()
        # print 'and it is:'  + s
        for line in lines:
            line = str(line)
            if not line.startswith(' ') and not line.startswith('mon.') and 'IEEE 802.11' in line:
                wlan = line.split(' ')[0]
                print('Wifi interface found: ' + wlan)

    if wlan == '':
        print('Wireless interface could not be found on your device.')
        return

    # print 'Verifying Internet connections'
    p = subprocess.Popen(['ifconfig'], stdout=subprocess.PIPE)
    out, err = p.communicate()
    lines = bitestring_to_string(out).splitlines()
    iface = []
    for line in lines:
        line = str(line)
        if not line.startswith(' ') and not line.startswith(wlan) and not line.startswith('lo') and not line.startswith(
                'mon.') and len(line) > 0:
            iface.append(line.split(' ')[0])
        # print 'f::' + line

    if len(iface) == 0:
        print('No network nic could be found on your deivce to interface with the LAN')
    elif len(iface) == 1:
        ppp = iface[0]
        print('Network interface found: ' + ppp)
    else:
        rniface = range(len(iface))
        s = ''
        while True:
            for i in rniface:
                print(i, iface[i])
            try:
                s = int(input("Enter number for internet supplying NIC :"))
            except:
                continue
            if s not in rniface:
                continue
            ppp = iface[s]
            break

    while True:
        IP = input('Enter an IP address for your ap [192.168.45.1] :')
        # except: continue
        # print type(IP)
        # sys.exit(0)
        if IP == None or IP == '':
            IP = '192.168.45.1'
        if not validate_ip(IP): continue
        break

    Netmask = '255.255.255.0'

    # CONFIGURE SSID, PASSWORD, ETC.
    SSID = input('Enter SSID [joe_ssid] :')
    if SSID == '': SSID = 'joe_ssid'
    password = input('Enter 10 digit password [1234567890] :')
    if password == '': password = '1234567890'

    f = open('run.dat', 'r')
    lout = []
    for line in f.readlines():
        lout.append(line.replace('<SSID>', SSID).replace('<PASS>', password))

    f.close()
    f = open('run.conf', 'w')
    f.writelines(lout)
    f.close()

    print('created hostapd configuration: run.conf')

    dc = {'wlan': wlan, 'inet': ppp, 'ip': IP, 'netmask': Netmask, 'SSID': SSID, 'password': password}
    json_object = json.dumps(dc, indent=4)

    # Writing to sample.json
    with open("hotspotd.json", "w") as outfile:
        outfile.write(json_object)
    print(dc)
    print('Configuration saved')


# CHECK WIFI DRIVERS AND ISSUE WARNINGS


def check_dependencies():
    p = subprocess.Popen(['hostapd'], stdout=subprocess.PIPE)
    one_process, err = p.communicate()
    if err:
        print('hostapd executable not found. Make sure you have installed hostapd.')
    p = subprocess.Popen(['dnsmasq'], stdout=subprocess.PIPE)
    second_process, err = p.communicate()
    if err:
        print('dnsmasq executable not found. Make sure you have installed dnsmasq.')

    if one_process != bytes() and second_process != bytes():
        print('hotspot is already running.')
        return False
    else:
        return True


def check_interfaces():
    global wlan, ppp
    print('Verifying interfaces')
    p = subprocess.Popen(['ifconfig'], stdout=subprocess.PIPE)
    process, err = p.communicate()
    lines = bitestring_to_string(process).splitlines()
    bwlan = False
    bppp = False

    for line in lines:
        if not line.startswith(' ') and len(line) > 0:
            text = line.split(' ')[0]
            if text.startswith(wlan):
                bwlan = True
            elif text.startswith('ppp0'):
                bppp = True

    if not bwlan:
        print(wlan + ' interface was not found. Make sure your wifi is on.')
        return False
    elif not bppp:
        print(ppp + ' interface was not found. Make sure you are connected to the internet.')
        return False
    else:
        print('done.')
        return True


def pre_start():
    try:
        oper = platform.linux_distribution()
        if oper[0].lower() == 'ubuntu' and oper[2].lower() == 'trusty':
            # trusty patch
            print('applying hostapd workaround for ubuntu trusty.')
            subprocess.run('nmcli nm wifi off')
            subprocess.run('rfkill unblock wlan')
            subprocess.run('sleep 1')
            print('done.')
    except:
        pass


def start_router():
    if not check_dependencies():
        return
    elif not check_interfaces():
        return
    pre_start()
    s = 'ifconfig ' + wlan + ' up ' + IP + ' netmask ' + Netmask
    print('created interface: mon.' + wlan + ' on IP: ' + IP)
    r = subprocess.run(s)
    subprocess.run('echo %s', r)
    # subprocess.run('echo  'sleeping for 2 seconds.')
    print('wait..')
    subprocess.run('sleep 2')
    i = IP.rindex('.')
    ipparts = IP[0:i]

    # stop dnsmasq if already running.
    if cli.is_process_running('dnsmasq') > 0:
        print('stopping dnsmasq')
        subprocess.run('killall dnsmasq')

    # stop hostapd if already running.
    if cli.is_process_running('hostapd') > 0:
        print('stopping hostapd')
        subprocess.run('killall hostapd')

    # enable forwarding in sysctl.
    print('enabling forward in sysctl.')
    r = cli.set_sysctl('net.ipv4.ip_forward', '1')
    print(r.strip())

    # enable forwarding in iptables.
    print('creating NAT using iptables: ' + wlan + '<->' + ppp)
    subprocess.run('iptables -P FORWARD ACCEPT')

    # add iptables rules to create the NAT.
    subprocess.run('iptables --table nat --delete-chain')
    subprocess.run('iptables --table nat -F')
    r = subprocess.run('iptables --table nat -X')
    if len(r.strip()) > 0: print(r.strip())
    subprocess.run('iptables -t nat -A POSTROUTING -o ' + ppp + ' -j MASQUERADE')
    subprocess.run('iptables -A FORWARD -i ' + ppp + ' -o ' + wlan + ' -j ACCEPT -m state --state RELATED,ESTABLISHED')
    subprocess.run('iptables -A FORWARD -i ' + wlan + ' -o ' + ppp + ' -j ACCEPT')

    # allow traffic to/from wlan
    subprocess.run('iptables -A OUTPUT --out-interface ' + wlan + ' -j ACCEPT')
    subprocess.run('iptables -A INPUT --in-interface ' + wlan + ' -j ACCEPT')

    # start dnsmasq
    s = 'dnsmasq --dhcp-authoritative --interface=' + wlan + ' --dhcp-range=' + ipparts + '.20,' + ipparts + '.100,' + Netmask + ',4h'
    print('running dnsmasq')
    r = subprocess.run(s)
    subprocess.run('echo %s',r)

    # ~ f = open(os.getcwd() + '/hostapd.tem','r')
    # ~ lout=[]
    # ~ for line in f.readlines():
    # ~ lout.append(line.replace('<SSID>',SSID).replace('<PASS>',password))
    # ~
    # ~ f.close()
    # ~ f = open(os.getcwd() + '/hostapd.conf','w')
    # ~ f.writelines(lout)
    # ~ f.close()

    # writelog('created: ' + os.getcwd() + '/hostapd.conf')
    # start hostapd
    # s = 'hostapd -B ' + os.path.abspath('run.conf')
    s = 'hostapd -B ' + os.getcwd() + '/run.conf'
    subprocess.run('echo running hostapd')
    # subprocess.run('echo 'sleeping for 2 seconds.')
    subprocess.run('echo wait..')
    subprocess.run('sleep 2')
    r = subprocess.run(s)
    subprocess.run('echo %s', r)
    print('hotspot is running.')
    return


def stop_router():
    # bring down the interface
    subprocess.run('ifconfig mon.' + wlan + ' down')

    # TODO: Find some workaround. killing hostapd brings down the wlan0 interface in ifconfig.
    # ~ #stop hostapd
    # ~ if cli.is_process_running('hostapd')>0:
    # ~ subprocess.run('echo  'stopping hostapd')
    # ~ subprocess.run('pkill hostapd')

    # stop dnsmasq
    if cli.is_process_running('dnsmasq') > 0:
        subprocess.run('echo  stopping dnsmasq')
        subprocess.run('killall dnsmasq')

    # disable forwarding in iptables.
    subprocess.run('echo disabling forward rules in iptables.')
    subprocess.run('iptables -P FORWARD DROP')

    # delete iptables rules that were added for wlan traffic.
    if wlan != None:
        subprocess.run('iptables -D OUTPUT --out-interface ' + wlan + ' -j ACCEPT')
        subprocess.run('iptables -D INPUT --in-interface ' + wlan + ' -j ACCEPT')
    subprocess.run('iptables --table nat --delete-chain')
    subprocess.run('iptables --table nat -F')
    subprocess.run('iptables --table nat -X')
    # disable forwarding in sysctl.
    subprocess.run('echo disabling forward in sysctl.')
    r = subprocess.run('net.ipv4.ip_forward', '0')
    print(r.strip())
    subprocess.run('ifconfig ' + wlan + ' down'  + IP + ' netmask ' + Netmask)
    subprocess.run('ip addr flush ' + wlan)
    print('hotspot has stopped.')
    return


if __name__ == "__main__":
    global wlan, ppp, IP, Netmask

    # TODO run script as root
    # check root or not
    # if os.getenv('USER') != 'root':
    # 	print("You need root permissions to do this, sloth!")
    # 	sys.exit(1)

    scpath = os.path.realpath(__file__)
    realdir = os.path.dirname(scpath)
    os.chdir(realdir)
    # print 'changed directory to ' + os.path.dirname(scpath)
    # if an instance is already running, then quit
    parser = argparse.ArgumentParser(description='A small daemon to create a wifi hotspot on linux')
    parser.add_argument('-v', '--verbose', required=False, action='store_true')
    parser.add_argument('command', choices=['start', 'stop', 'configure'])
    args = parser.parse_args()
    import sys

    newconfig = False
    if not os.path.exists('hotspotd.json'):
        configure()
        newconfig = True
    f = open('hotspotd.json')
    dc = json.load(f)
    wlan = dc['wlan']
    ppp = dc['inet']
    IP = dc['ip']
    Netmask = dc['netmask']
    SSID = dc['SSID']
    password = dc['password']

    args = sys.argv[-1]
    if args == 'configure':
        if not newconfig: configure()
    elif args == 'stop':
        stop_router()
    elif args == 'start':
        start_router()
