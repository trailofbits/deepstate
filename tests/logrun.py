from __future__ import print_function
import subprocess
import time

def logrun(cmd, file, timeout):
    with open(file, 'w') as outf:
        p = subprocess.Popen(cmd, stdout=outf, stderr=outf)
    start = time.time()
    oldContents = ""
    while (p.poll() is None) and ((time.time() - start) < timeout):
        with open(file, 'r') as inf:            
            contents = inf.read()
        if len(contents) > len(oldContents):
            print(contents[len(oldContents):], end="")
            oldContents = contents
        time.sleep(1)
    print()
    if p.poll() is None:
        return ("TIMEOUT", contents)
    return (p.returncode, contents)
        
