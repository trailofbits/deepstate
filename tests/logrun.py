from __future__ import print_function
import subprocess
import time
import sys

def logrun(cmd, file, timeout):
    with open(file, 'w') as outf:
        p = subprocess.Popen(cmd, stdout=outf, stderr=outf)
    start = time.time()
    oldContents = ""
    while (p.poll() is None) and ((time.time() - start) < timeout):
        with open(file, 'r') as inf:            
            contents = inf.read()
        if len(contents) > len(oldContents):
            sys.stderr.write(contents[len(oldContents):])
            sys.stderr.flush()
            oldContents = contents
        time.sleep(1)
    sys.stderr.write("\n")
    if p.poll() is None:
        return ("TIMEOUT", contents)
    if "internal error" in contents:
        return ("INTERNAL ERROR", contents)
    if "Traceback (most recent call last)" in contents:
        return ("EXCEPTION RAISED", contents)    
    return (p.returncode, contents)
        
