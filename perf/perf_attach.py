import pyinotify
import subprocess
import sys
import re
import os
import time
import signal
import psutil
from optparse import OptionParser

watch_manager = pyinotify.WatchManager()
wd_dict = dict() 

# Parameters to use with ATLAS Kit Validation:
# Path: /tmp
# Filename: AtlasG4_trf.log
# Begin: start processing event #72
# End: done processing event #72
# Process name: athena.py
#

def cmdline():
    parser = OptionParser()

    parser.add_option("-p", "--path",
        action="store", type="string", dest="path",
        default=None,
        help="Path to be watched")

    parser.add_option("-f", "--file-name",
        action="store", type="string", dest="file_name",
        default=None,
        help="File to be watched")

    parser.add_option("", "--begin",
        action="store", type="string", dest="begin",
        default=None,
        help="Begin pattern")

    parser.add_option("", "--end",
        action="store", type="string", dest="end",
        default=None,
        help="End pattern")

    parser.add_option("", "--process-name",
        action="store", dest="process_name",
        default= None,
        help="Name of the process to attach perf to")
    
    options = parser.parse_args()[0]
    return options, parser


class PerfStrategy:
    def __init__(self, pid, begin, end):
        self.pid = pid
        # Begin and end patterns
        self.begin = begin
        self.end = end
        self.p = None
        self.sentinel = None

    def parse(self, line, *args):
        regex_pattern = re.compile(self.begin)
        group = re.search(regex_pattern, line)
        if group != None and self.p == None:
            sys.stderr.write("Starting perf on pid {}\n".format(self.pid))
            # Executing perf and waiting for end pattern.
            # When attaching perf to a process, the sampling time is determined
            # by the command passed to perf. In the first version strace was i
            # used to catch exit_group (assuming the process does exit with 
            # exit_group). This would monitor up to the end of the run. Now 
            # helper command is simply a sleep which is killed upon encountering 
            # end pattern
            self.p = subprocess.Popen(["/usr/bin/perf", "record", 
                                       "-e cycles:pp", "-p", str(self.pid),
                                       "sleep", "infinity"],
                                       stderr = subprocess.PIPE)

        regex_pattern = re.compile(self.end)
        group = re.search(regex_pattern, line)
        if group != None and self.p != None:
            sys.stderr.write("Terminating perf on pid {}\n".format(self.pid))
            # Searching for perf children. There should be only one, i.e. "sleep infinity"
            perf_process = psutil.Process(self.p.pid)
            if(len(perf_process.children(recursive = False)) > 1):
                sys.stderr.write("perf has more than one children, don't know which one to kill")
                sys.exit(1)
            else:
                os.kill(perf_process.children(recursive = False)[0].pid, signal.SIGTERM)

            stdout, stderr = self.p.communicate()
            sys.stdout.write(str(stderr))
            self.p = None
            sys.exit(0)

class PerfEventHandler(pyinotify.ProcessEvent):

    def __init__(self, file_name, process_name, begin, end):
        # fd of the file being monitored
        self.fd = None
        self.perf_strategy = None
        self.bytes_read = 1
        self.file_name = file_name
        self.process_name = process_name
        self.begin = begin
        self.end = end

    def process_IN_CREATE(self, event):
        global wd_dict
        if os.path.isdir(event.pathname) and event.pathname not in wd_dict.values():
            wd_temp = watch_manager.add_watch(event.pathname,
                                              pyinotify.IN_OPEN | 
                                              pyinotify.IN_CREATE,
                                              rec = True)
            if(wd_temp[event.pathname] > 0):
                wd_dict = dict(wd_dict.items() + wd_temp.items())
            else:
                sys.sterr.write("Error while adding watch to {}".format(event.pathname))


    def process_IN_OPEN(self, event):
        global wd_dict
        # Note: if IN_OPEN takes too much time to execute, other events might get lost
        if event.pathname[-len(self.file_name):] == self.file_name:
            sys.stderr.write("IN_OPEN: {}\n".format(event.pathname))
            # If process name is not set, profile the application that 
            # is writing on the log file
            pid = -1
            if self.process_name == None:
                p = subprocess.Popen(["lsof", "-F", "p", event.pathname], 
                                     stdout = subprocess.PIPE)
                stdout = p.communicate()[0]
                for line in stdout.split("\n"):
                    try:
                        if line[0] == "p":
                            pid = int(line[1:])
                            break
                    except:
                        pass
            else:
                attempts = 3
                while(pid == -1 and attempts != 0):
                    for _pid in psutil.pids():
                        try:
                            p = psutil.Process(_pid)
                            if p.name() == self.process_name:
                                pid = _pid
                        except Exception, e:
                            pass
                    attempts-=1
                    time.sleep(1)
            if pid == -1:
                sys.stderr.write("Could not find process to attach to\n")
                sys.exit(1)

            if(self.perf_strategy == None):
                self.perf_strategy = PerfStrategy(pid, self.begin, self.end)
                sys.stderr.write("Registered a perf strategy for pid {}\n".format(pid))

            for watch_path in wd_dict.keys():
                try:
                    watch_manager.rm_watch(wd_dict[watch_path], rec = True)
                except Exception, e:
                    pass

            # Adding a watch directly for the file but only for the following 
            # events (this is what tail -f does)
            # pyinotify.IN_MODIFY      | pyinotify.IN_ATTRIB |
            # pyinotify.IN_DELETE_SELF | pyinotify.IN_MOVE_SELF
            wd_temp = watch_manager.add_watch(event.pathname,
                                              pyinotify.IN_MODIFY | 
                                              pyinotify.IN_ATTRIB |
                                              pyinotify.IN_DELETE_SELF | 
                                              pyinotify.IN_MOVE_SELF,
                                              rec=True)
            if(wd_temp[event.pathname] > 0):
                wd_dict = dict(wd_dict.items() + wd_temp.items())
                sys.stderr.write("IN_MODIFY watch created for {}\n".format(event.pathname))
            else:
                sys.stderr.write("Could not add modify watch for file {}\n", event.pathname)

            # Opening the file to have file descriptor available during
            # IN_MODIFY callback
            try:
                self.fd = open(event.pathname, "r")
            except IOError, e:
                sys.stderr.write("Could not open {} for reading: {}".format(event.pathname, e))
                sys.exit(1)

    def process_IN_MODIFY(self, event):
        # Seek at the end, as EOF had alredy been reached an would not work after
        # the first seek
        self.fd.seek(self.bytes_read - 1, 0)
        # Read until EOF is reached without argument
        data = self.fd.read()
        self.bytes_read += len(data)
        self.perf_strategy.parse(data)
def main():

    global wd_dict
    options, parser = cmdline()
    try:
        if(options.path == None):
            raise ValueError("path was not specified") 
        if(options.file_name == None):
            raise ValueError("file name was not specified")
        if(options.begin == None):
            raise ValueError("begin pattern was not specified")
        if(options.end == None):
            raise ValueError("end pattern was not specified")
    except Exception, e:
        sys.stderr.write("Error: {}\n".format(str(e)))
        parser.print_help()
        sys.exit(1)
         
    path = options.path
    wd_dict = watch_manager.add_watch(path, pyinotify.IN_CREATE | pyinotify.IN_OPEN, rec=True)
    if wd_dict[path] > 0 :
        sys.stdout.write("Watch created correctly on {} with wd {}\n".format(path, wd_dict[path]))
    else:
        sys.stderr.write("Error while creating watch")
        sys.exit(1)

    event_handler = PerfEventHandler(options.file_name, 
                                     options.process_name,
                                     options.begin,
                                     options.end)
    notifier = pyinotify.Notifier(watch_manager, event_handler)
    notifier.loop()

if __name__ == '__main__':
    main()
