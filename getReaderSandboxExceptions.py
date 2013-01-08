''' http://blog.binamuse.com/2013/01/uncover-adobe-reader-x-sandbox.html '''
from winappdbg import Debug, Process, version
import sys, os, hashlib, struct

class PMF(object):
    autocommit = False
    columns = [(0x00009c98, "Architecture"),
               (0x9c93,'Authentication ID'),
               (0x9c96,'Category'),
               (0x9c82,'ComandLine'),
               (0x9c82,'Company'),
               (0x9c74,'Date & Time'),
               (0x9c81,'Description'),
               (0x9c79,'Detail'),
               (0x9c8d,'Duration'),
               (0x9c92,'Event Class'),
               (0x9c84,'Image Path'),
               (0x9c95,'Integrity'),
               (0x9c77,'Operation'),
               (0x9c97,'Parent PID'),
               (0x9c87,'Path'),
               (0x9c76,'PID'),
               (0x9c75,'Process Name'),
               (0x9c8c,'Relative Time'),
               (0x9c78,'Result'),
               (0x9c7a,'Sequence'),
               (0x9c85,'Session'),
               (0x9c88,'TID'),
               (0x9c8e,'Time Of Day'),
               (0x9c83,'User'),
               (0x9c91,'Version'),
               (0x9c94,'Virtualized'),
               ]
    relations = [ 'is', 'is not', 'less than', 'more than', 'begins with', 'ends with', 'contains', 'excludes' ]
    actions = ["EXCLUDE", "INCLUDE"]
    def unpack(self, fmt):
        assert len(fmt) in [1,2]
        return struct.unpack(fmt,self.f.read(len(struct.pack(fmt,0))))[0]
    def read_byte(self):
        return self.unpack("B")
    def read_int(self):
        return self.unpack("<L")
    def read_string(self):
        size = self.unpack("<L")
        return self.f.read(size)

    def pack(self, fmt, val):
        assert len(fmt) in [1,2]
        self.f.write(struct.pack(fmt,val))
    def write_byte(self,val):
        return self.pack("B",val)
    def write_int(self,val):
        return self.pack("<L",val)
    def write_string(self,val):
        val = unicode(val).encode("utf-16")[2:]
        self.pack("<L", len(val))
        return self.f.write(val)

    def __init__(self, filename):
        self.rules = []
        try:
            self.f = file(filename,'r+')
            self.read_int() #size in bytes
            self.read_byte() #version ?
            n=self.read_int()
            for i in range(0,n):
                col = self.read_int()
                rel = self.read_int()
                action = self.read_byte()
                value = self.read_string()
                self.f.read(8)
                self.rules.append((i,col,rel,action,value))
        except Exception,e:
            print "Could not read file.",e
            self.f = file(filename,'w+b')
        self.f.seek(0)

    def __str__(self):
        ret  = "ID    Column                  Relation        Value           Action          \n"
        for rule_id, col,rel,action,value in self.rules:
            ret += str(rule_id).ljust(6,' ')
            ret += ("%s"%dict(PMF.columns).setdefault(col, "%04x"%col )).ljust(24,' ')
            ret += ("%s"%PMF.relations[rel]).ljust(16,' ')
            ret += (value.replace('\x00','')).ljust(16,' ')
            ret += (PMF.actions[action]).ljust(16,' ')
            ret += "\n"
        return ret

    def append(self, col,rel,value,action):
        assert col in [x[1] for x in PMF.columns]
        assert rel in PMF.relations
        assert action in PMF.actions
        assert type(value) in [str, unicode]

        rule_id = max([0] + [ x[0] for x in self.rules])+1 
        self.rules.append(( rule_id,
                      [x[0] for x in PMF.columns if x[1]==col][0],
                      PMF.relations.index(rel),
                      PMF.actions.index(action),
                      unicode(value+'\x00')))

        #check for duplicates and rollback
        if len(set([x[1:] for x in self.rules])) != len(self.rules):
            self.remove(rule_id)
            raise Exception("Duplicated Rule")

        return rule_id

    def remove(self, rule_id):
        self.rules = [x for x in self.rules if x[0] != rule_id]

    def clear(self):
        self.rules = []

    def lst(self):
        ret = []
        for rule_id, col,rel,action,value in self.rules:
            ret.append( (rule_id,
                         dict(PMF.columns)[col],
                         PMF.relations[rel],
                         unicode(value),
                         PMF.actions[action] ))
        return ret

    def commit(self,offset=0):
        self.f.seek(offset+4)

        self.write_byte(1) #version ?
        self.write_int(len(self.rules))
        for rule_id, col,rel,action,value in self.rules:
            self.write_int(col)
            self.write_int(rel)
            self.write_byte(action)
            self.write_string(unicode(value))
            self.f.write("\x00"*8)
        size = self.f.tell()-offset-4
        self.f.seek(offset)
        self.write_int(size)
        self.f.seek(size+offset+4)
        self.f.truncate()

    def __del__(self):
        try:
            if PMF.autocommit:
                self.commit()
        except:
            pass

subsystems = [
    'SUBSYS_FILES',             # Creation and opening of files and pipes.
    'SUBSYS_NAMED_PIPES',       # Creation of named pipes.
    'SUBSYS_PROCESS',           # Creation of child processes.
    'SUBSYS_REGISTRY',          # Creation and opening of registry keys.
    'SUBSYS_SYNC',              # Creation of named sync objects.
    'SUBSYS_HANDLES'            # Duplication of handles to other processes.
  
]
semantics = {}
semantics['10.1.5']=semantics['10.1.4']=semantics['10.1.3']=[
    'FILES_ALLOW_ANY',       # Allows open or create for any kind of access
                             # that the file system supports.
    'FILES_ALLOW_READONLY',  # Allows open or create with read access only.
    'FILES_ALLOW_QUERY',     # Allows access to query the attributes of a file.
    'FILES_ALLOW_DIR_ANY',   # Allows open or create with directory semantics
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    'REG_ALLOW_READONLY',
    '11',
    '12',
    'REG_ALLOW_ANY',
]

semantics['11.0.0']=semantics['11.0.1']=[
    'FILES_ALLOW_ANY',       # Allows open or create for any kind of access
                             # that the file system supports.
    'FILES_ALLOW_READONLY',  # Allows open or create with read access only.
    'FILES_ALLOW_QUERY',     # Allows access to query the attributes of a file.
    'FILES_ALLOW_DIR_ANY',   # Allows open or create with directory semantics
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    '10',
    '11',
    'REG_ALLOW_READONLY',
    '13',
    '14',
    '15',
    'FILES_REJECT',
    'REG_ALLOW_ANY',
]


def print_policy(event):
    #get process, thread and stak pointer
    process = event.get_process()
    thread = event.get_thread()
    stack = thread.get_sp()

    #read the 3 arguments from the debugee memory
    subsystem = process.read_pointer(stack+0x4)
    semantic = process.read_pointer(stack+0x8)
    value_p = process.read_pointer(stack+0xC)
    value = process.read(value_p, 2)
    while value[-2:] != '\x00\x00':
        value += process.read(value_p+len(value),2)
    value = value[:-2].decode('utf-16')

    #Try to handle wildcards (FIX!)
    if value.startswith("\\??\\pipe\\"):
        value = value[9:]
    if '?' in value:
        value = value.split('?')[0]
    if value.endswith('*'):
        value = value[:-1]
    if value.startswith('*'):
        value = value[1:]
    if value == '':
        return

    print "Rule: %d, %d, %s"%(subsystem,semantic,value)

    if subsystem == 0:
        #Files
        if semantics[semantic] == 'FILES_ALLOW_ANY':
            event.debug.pmf.append("Path","contains", value, "INCLUDE")
        else:
            event.debug.pmf.append("Path","contains", value, "EXCLUDE")
    elif subsystem == 3:
        #Registry
        if semantics[semantic] == 'REG_ALLOW_READONLY':
            event.debug.pmf.append("Path","contains", value, "EXCLUDE")
        elif  semantics[semantic] == 'REG_ALLOW_ANY':
            event.debug.pmf.append("Path","contains", value, "INCLUDE")
    else:
        pass


if __name__ == '__main__':
    print "Wellcome. Using Winappdbg version", version
    #Instantiate the debugger
    debug = Debug(bKillOnExit=True, bHostileCode=True)
    #Build the basic set of filter rules
    pmf = PMF('policy.pmf')
    pmf.clear()
    pmf.append('Process Name','is', 'Procmon.exe', 'EXCLUDE')
    pmf.append('Process Name','is', 'System', 'EXCLUDE')
    pmf.append('Operation','begins with', 'IRP_MJ_', 'EXCLUDE')
    pmf.append('Operation','begins with', 'FASTIO_', 'EXCLUDE')
    pmf.append('Result','begins with', 'FAST IO', 'EXCLUDE')
    pmf.append('Path','ends with', 'pagefile.sys', 'EXCLUDE')
    pmf.append('Path','ends with', '$Mft', 'EXCLUDE')
    pmf.append('Path','ends with', '$MftMirr', 'EXCLUDE')
    pmf.append('Path','ends with', '$LogFile', 'EXCLUDE')
    pmf.append('Path','ends with', '$Volume', 'EXCLUDE')
    pmf.append('Path','ends with', '$AttrDef', 'EXCLUDE')
    pmf.append('Path','ends with', '$Root', 'EXCLUDE')
    pmf.append('Path','ends with', '$Bitmap', 'EXCLUDE')
    pmf.append('Path','ends with', '$Boot', 'EXCLUDE')
    pmf.append('Path','ends with', '$BadClus', 'EXCLUDE')
    pmf.append('Path','ends with', '$Secure', 'EXCLUDE')
    pmf.append('Path','ends with', '$UpCase', 'EXCLUDE')
    pmf.append('Path','contains', '$Extend', 'EXCLUDE')
    pmf.append('Event Class','is', 'Profiling', 'EXCLUDE')
    pmf.append('Event Class','is', 'Registry', 'EXCLUDE')
    pmf.append('Event Class','is', 'Network', 'EXCLUDE')
    pmf.append('Event Class','is', 'Process', 'EXCLUDE')
    pmf.append("Integrity","is", "Low", "EXCLUDE")


    #Read Adobe Reader Executable file and determine the version using hardcoded hashes
    versions = { '84b3c0476d17c9a44db4c9256a7e2844': '10.1.3', 
                 'c1648084c395152fbfa1b333d92056bc': '10.1.4',
                 '5aa4df6cd3c96086955064bec1cd0c9b': '10.1.5',
                 'ca0c67ba7aeba6aed5ddb852e6eea811': '11.0.0',
                 '4cb25d0504423d7bccb9c547e253a67f': '11.0.1', }

    program_files = r"C:\Program Files"
    if os.path.exists(r"C:\Program Files (x86)"):
        program_files = r"C:\Program Files (x86)"
    try:
        path = program_files+r"\Adobe\Reader 11.0\Reader\AcroRd32.exe"
        version = versions[hashlib.md5(file(path,"rb").read()).hexdigest()]  #raise if version not supported
    except:
        path = program_files+r"\Adobe\Reader 10.0\Reader\AcroRd32.exe"
        version = versions[hashlib.md5(file(path,"rb").read()).hexdigest()]  #raise if version not supported

    print "Adobe Reader X %s"%version
    semantics = semantics[version]

    #Run the reader!
    debug.execl(path)
    debug.pmf = pmf
    broker = Process(debug.get_debugee_pids()[0])
    print "Broker PID: %d"%broker.get_pid()

    # Loop while calc.exe is alive and the time limit wasn't reached.
    while debug:
        # Get the next debug event.
        event = debug.wait()

        # Dispatch the event and continue execution.
        try:
            debug.dispatch(event)
            # add breakpoint when acrord32 gets loaded
            if event.get_event_code() == 3:
                process = event.get_process()
                base_address = event.get_image_base()
                print "AcroRd32 Main module found at %08x"%base_address

                # Hint: Use the string "Check failed: policy_." to hunt 
                # the function that adds a new policy
                breakpoint_offsets = { "10.1.3": 0x21260,
                                       "10.1.4": 0x21630,
                                       "10.1.5": 0x1fca0,
                                       "11.0.0": 0x20370,
                                       "11.0.1": 0x18350, }
                breakpoint_address = base_address + breakpoint_offsets[version]

                #setting breakpoint
                print "Setting breakpoint at %08x"%breakpoint_address
                debug.break_at(process.get_pid(), breakpoint_address, print_policy)

        except Exception,e:
            print "Exception in user code:",e
        finally:
            debug.cont(event)

    # Stop the debugger.
    debug.stop()
    pmf.commit()

