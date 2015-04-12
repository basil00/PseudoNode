#!/usr/bin/python

import re

addr_re = r'\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}'

def parse_from_file(fName):
    """
    return a addr dict
    """
    addrs = {}
    with open(fName) as f:
        while 1:
            line = f.readline()
            if line== '':
                break
            else:
                res = re.search(addr_re,line,re.I)
                if res == None: continue
                if addrs.get(res.group()) == None:
                    addrs[res.group()] = 1
                else:
                    continue
    return addrs

if __name__ == '__main__':
    import sys
    addrs =  parse_from_file(sys.argv[1])
    print(len(addrs))
