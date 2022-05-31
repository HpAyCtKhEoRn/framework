class Scan:
    def __init__(self, host, ports, N_THREADS):
        init()
        self.host=host
        self.N_THREADS=N_THREADS
        self.GREEN = Fore.GREEN
        self.RESET = Fore.RESET
        self.GRAY = Fore.LIGHTBLACK_EX
        self.q = Queue()
        self.print_lock = Lock()
        for worker in ports:
            self.q.put(worker)
        for t in range(self.N_THREADS):
            Thread(target=self.scan_thread, daemon = True).start()
        self.q.join()

    def port_scan(self, port):
        try:
            s = socket.socket()
            s.connect((self.host, port))
            print(f"{self.GREEN}{port} is open    {self.RESET}")
            s.close()
        except:
            print(f"{self.GRAY}{port} is closed  {self.RESET}", end='\r')
        

    def scan_thread(self):
        while True:
            worker = self.q.get()
            self.port_scan(worker)
            self.q.task_done()

def check_correctness_port_scan(args):
    try:
        Threads=args.Threads_to_scan
        IP=args.Host
        Ports=args.Port_range.split('-')
        if len(Ports) > 1:
            Ports = [i for i in range(Ports[0], Ports[-1])]
        from tools import is_ip
        if not is_ip(IP):
            exit("[-] Incorrect input IP!")
#        start_port, end_port = args.Port_range.split("-")
#        ranges=[ p for p in range(int(start_port), int(end_port))]
    except:
        exit("[-] Incorrect input data! You must write python3 exemple.py ... --Port_range ... --Threads ...! For more information, see 'python3 exemple.py -h'.")
    print('[+] Data is entered correctly.             \n[*] Loading...                ', end='\r')
    return IP, Ports, Threads
