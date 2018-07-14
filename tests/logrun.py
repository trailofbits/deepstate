from __future__ import print_function
import subprocess
import time
import sys

def logrun(cmd, file, timeout):
    sys.stderr.write("=" * 80 + "\n")
    sys.stderr.write("RUNNING: ")
    sys.stderr.write(" ".join(cmd) + "\n")
    sys.stderr.flush()
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
        time.sleep(0.05)
    totalTime = time.time() - start
    sys.stderr.write("\n")
    rv = (p.returncode, contents)    
    if p.poll() is None:
        rv = ("TIMEOUT", contents)
    if "Traceback (most recent call last)" in contents:
        rv = ("EXCEPTION RAISED", contents)
    if "internal error" in contents:
        rv = ("INTERNAL ERROR", contents)
    sys.stderr.write("\nDONE\n\n")
    sys.stderr.write("TOTAL EXECUTION TIME: " + str(totalTime) + "\n")
    sys.stderr.write("RETURN VALUE: " + str(p.returncode) + "\n")
    sys.stderr.write("RETURNING AS RESULT: " + str(rv[1]) + "\n")
    sys.stderr.write("=" * 80 + "\n")    
        

        
