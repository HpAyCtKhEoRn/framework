from argparse import ArgumentParser
from threading import Thread

#Главная
parser = ArgumentParser(description='Hacker`s framework')
parser.add_argument('--Main_choice', dest="Main_Choice", default=None, help='Main : It is the main choice. You can write there one of the functions. They are : Arp_spoof, Mac_IP_Chenge, Dos, Dns_spoof, Port_scan, Browser_snif, UDP_attack, You may write one or some(with dots).')
#Арп спуфер
parser.add_argument('--forwarding', dest="Forward", default=None, help='Arp spoof : Forwarding may be 0 or 1:\n0 - Packets will not be forwarded and the target will not be able to access the internet\n1-Packets can be redirected and can be read by a sniffer.')
parser.add_argument('--cycle', dest="Cycle", default=None, help='Arp spoof : It is cycle of victim information update - The more, the faster and less accurate the spouffer. The smaller, the slower and more accurate the spoofer. The average value is 100.')
parser.add_argument('--threads', dest="Threads", default=None, help='Arp spoof : It is a number of threads. This parametr should not exceed the number of processors in your device!')
parser.add_argument('--target', dest="Target", default=None, help='It is IP of target device.')
parser.add_argument('--name', dest="Name", default=None, help='The name of this IP. If you entered only IP - you will spoof this IP. If you entered IP and name - this name will be matched with this IP in the database. If you entered only name - you will spoof the IP? what is matched with this name.')
# ченджер
parser.add_argument('--new_value', dest='New_value', default=None, help='Mac and IP Chenger : Enter in this input new value for your -c.')
parser.add_argument('--interface', dest='Interface', default=None, help='Mac and IP Chenger : Enter in this input Interface? on what you want to change Mac. All interfaces you will see with ipconfig(For Windows) or ifconfig(For Linux and MacOS).')
parser.add_argument('--choice', dest='Choice', default=None, help='Mac and IP Chenger : It may be Mac or IP - choice, what you want to change.')
#досер
parser.add_argument('--url', dest='URL', default=None, help='Dos : This is url to dos.')
parser.add_argument('--Threads', dest='threads', default=20, help='Dos : This is number of threads of dos, default is 20.')
parser.add_argument('--timeout', dest='Time', default=None, help='Dos : This is timeout of the checking speed of this app.')
#днс спуфер
parser.add_argument("--pages_to_spoof", dest="Pages", default=None, help="Dns Spoofer : Spoofing pages, using dot. Obligatory field.")
parser.add_argument("--spoof_ip", dest="Spoof_ip", default=None, help="Dns Spoofer : IP which the user goes to when visiting a blocked site. Required if -b is 0 or not specified!")
parser.add_argument("--spoof_port", dest="Spoof_port", default=None, help="Dns Spoofer : Port which the user goes to when visiting a blocked site. Required if -b is 0 or not specified!")
parser.add_argument("--blocked", dest="Blocked", default=0, help="Dns Spoofer : Can be 1 or 0. If 1 or not specified then the -p and -i fields do not need to be entered, and also everything specified in -p will be blocked for the target and he will not be able to access them. If set to 0, then the -p and -i fields are required and if the target traverses spoof pages , then its request will traverse to IP -i using the -p port.")
#Сканер портов
parser.add_argument("--host", dest="Host", help="Host to scan.")
parser.add_argument("--ports", dest="Port_range", default="1-65535", help="Port scanner : Port range to scan, default is 1-65535 (all ports)")
parser.add_argument("--Threads_to_scan", dest="Threads_to_scan", default="200", help="Port scanner : Threads to scan, default is 200")
#Сниффер браузеров
parser.add_argument("--Interface", dest="interface", default='', help="Browser Snif : This is an interface, what you will see in a terminal/cmd by command ipconfig(Windows) or ifconfig(Linux/MacOS)")
#ЮдП атака
parser.add_argument("--ip", dest="IP", default=None, help="UDP attacker : Target IP.")
parser.add_argument("--Threads_to_spoof", dest="Threads_to_spoof", default=None, help="UDP attacker : Threads to spoof.")

args = parser.parse_args()
main_choices=['arp_spoof', 'mac_ip_chenge', 'dos', 'dns_spoof', 'port_scan', 'browser_snif', 'udp_attack']

print('[*] Checking corectness of data...                       ', end='\r')

try:
    main_choice=args.Main_Choice.lower()
except:
    exit('[-]Main is the obligatory field! See "sudo python3 main.py --help".')

if main_choice == 'arp_spoof':
    from functions.spoofs import check_correctness_arpspoof_and_name, Arp_spoof
    Arp_spoof(check_correctness_arpspoof_and_name(args))
elif main_choice == 'mac_ip_chenge':
    from functions.chengers import check_correctness_chenger, change_mac_or_ip
    change(check_correctness_chenger(args))
elif main_choice == 'dos':
    from functions.spams import check_correctness_data_dos, dos
    dos(check_correctness_data_dos(args))
elif main_choice == 'dns_spoof':
    from functions.spoofs import check_correctness_dnsspoof, Dns_spoof
    Dns_spoof(check_correctness_dnsspoof(args))
elif main_choice == 'port_scan':
    from functions.scanners import check_correctness_port_scan, Scan
    Scan(check_correctness_port_scan(args))
elif main_choice == 'browser_snif':
    from functions.spoofs import check_correctness_snif, Sniff_data_browser
    Sniff_data_browser(check_correctness_snif(args))
elif main_choice == 'udp_attack':
    from functions.spams import check_correctness_udp_spam, udp_attack
    udp_attack(check_correctness_udp_spam(args))
else:
    exit(f'[+-] \'{main_choice}\' is unknown option. There are known options:\n'+'\n'.join([main_choices[i] for i in range(len(main_choices))]))
