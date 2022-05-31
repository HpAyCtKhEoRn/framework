def is_ip(ip):
    coors=0
    try:
        nums=ip.split('.')
        if len(nums) == 4:
            for i in nums:
                if i.isdigit() == False:
                    return False
                else:
                    coors+=1
        else:
            return False
    except:
        return 0
    if coors == 4:
        return True
    else:
        return False
