def change_mac_or_ip(new_value, interface, choice):
    slovar={'mac':' hw ether ', 'ip':' inet '}
    try:
        call(f"sudo ifconfig {interface}{slovar[choice]}{new_value}", shell=True)
        try:
            ifc=check_output('ifconfig', shell=True)
        except:
            ifc=check_output('ipconfig', shell=True)
        if new_mac in str(ifc):
            print(f"MAC изменен на {new_value}!")
        else:
            print(f"[-] Не получилось изменить {choice.upper()}!")
    except:
        print(f"[-] Не получилось изменить {choice.upper()} из-за ошибки!")

def check_correctness_chenger(args):
    try:
        new_value=args.New_value
        interface=args.Interface
        ch=(args.Choice).replace(' ', '').lower()
        if ch != 'mac' and ch != 'ip' or not new_value or not interface or not ch:
            exit('[-] Incorrect input data! See "python3 exemple.py -h".')
    except:
        exit('[-] Incorrect input data! See "python3 exemple.py -h".')
    print('[+] Data is entered correctly.             \n[*] Loading...                ', end='\r')
    return new_value, interface, ch
