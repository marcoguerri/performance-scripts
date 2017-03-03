#!/usr/bin/env python
# Parses mix reports obtained with Intel Software Development Emulator
# Correctly parses output Intel SDE 7.49.0-2016-07-07. Does not parse
# output of Intel SDE 7.58.0-2017-01-23

import pprint
import sys
import re
import tabulate
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.pylab as pylab
import traceback
from collections import OrderedDict
from optparse import OptionParser
from collections import deque

def get_exception_info():
    exc_type, _, exc_tb = sys.exc_info()
    traceback_first_entry = traceback.extract_tb(exc_tb)[-1]
    return (traceback_first_entry[0], traceback_first_entry[1], exc_type)

def cmdline():
    parser = OptionParser()
    parser.add_option("-f", "--first",
        action="store", type="string", dest="first",
        default=None,
        help="Specifies path of the first SDE report")

    parser.add_option("-s", "--second",
        action="store", type="string", dest="second",
        default=None,
        help="Specifies path of the second SDE report")

    parser.add_option("", "--func",
        action="store", type="string", dest="func",
        default=None,
        help="Specifies the name of the function to produce a report for ")

    parser.add_option("", "--list",
        action="store_true", dest="list",
        default=False,
        help="Returns a list of function from the two execution in order of runtime")

    parser.add_option("", "--graph",
        action="store_true", dest="graph",
        default=False,
        help="Generates a graph of the instructions (use with --func)")

    parser.add_option("", "--save",
        action="store_true", dest="save",
        default=False,
        help="Saves histogram on filesystem")
    
    parser.add_option("", "--labels",
        action="store", type="string", dest="labels",
        default  = ",",
        help="A coma separated pair of labels for Run 1 and Run2")

    options = parser.parse_args()[0]
    return options, parser


class Instruction(object):

    def __init__(self, opcode, count):
        self._opcode = opcode
        self._count = int(count)

    def opcode(self):
        return self._opcode

    def count(self):
        return self._count

    def __gt__(self, rhs):
        if(self._count == rhs._count):
            # If same count, instruction is greater if opcode is lower
            return self._opcode < rhs._opcode
        else:
            return self._count > rhs._count

    def __lt__(self, rhs):
        if(self._count == rhs._count):
            # If same count, instruction is lower if opcode is greater
            return self._opcode > rhs._opcode
        else:
            return self._count < rhs._count

    def __ge__(self, rhs):
        if(self._count == rhs._count):
            # If same count, instruction is greater if opcode is lower
            return self._opcode <= rhs._opcode
        else:
            return self._count >= rhs._count

    def __le__(self, rhs):
        if(self._count == rhs._count):
            # If same count, instruction is lower if opcode is greater
            return self._opcode >= rhs._opcode
        else:
            return self._count <= rhs._count

    def __eq__(self, rhs):
        # Equal comparision considers ONLY opcode
        return self._opcode == rhs._opcode

    def __str__(self):
        return "{} {}".format(self._opcode, self._count)

    def __repr__(self):
        return "{} {}".format(self._opcode, self._count)

class Heap:

    def __init__(self):
        self.l = deque()

    def add(self, inst):
        self.l.append(inst)
        self.heapify()

    def pop(self):
        try:
            el =  self.l.popleft()
            self.heapify()
            return el
        except IndexError:
            return None

    def heapify(self):
        for i in list(reversed(range(0, len(self.l)/2))):
            self._do_heapify(i)

    def __len__(self):
        return len(self.l)

    def _do_heapify(self, i):
        _max = self.l[i]
        _max_index = i
        if(i*2 + 2 < len(self.l)):
            if(self.l[i*2 + 2] > _max):
                _max = self.l[i*2 + 2]
                _max_index = i*2 + 2
        if(i*2 + 1 < len(self.l)):
            if(self.l[i*2 + 1] > _max):
                _max = self.l[i*2 + 1]
                _max_index = i*2 + 1
        if(_max_index != i):
            temp = self.l[i]
            self.l[i] = self.l[_max_index]
            self.l[_max_index] = temp
            self._do_heapify(_max_index)

    def pop_out_of_order(self, el):
        r = filter(lambda x: x == el, self.l)
        if(len(r) != 1):
            raise Exception("looked up {} opcodes {}".format(el, len(r)))

        del self.l[list(self.l).index(r[0])]
        return r[0]

    def __str__(self):
        return str(self.l)

class OutsideFunctionAssemblyBreakdownParser:
    def __init__(self):
        self.regex_func = re.compile(r"dynamic-counts-for-function: ([^\s]*)[^:]*:\s([^\s]*)")
    def parse(self, _iter, instance):
        line = _iter.next()
        g = re.search(self.regex_func, line)
        if(g != None):
            func_name, module = g.groups()[0], g.groups()[1]
            instance.last_state_transition_input = (func_name, module)
            instance.state = instance.inblock_parser

class InsideFunctionAssemblyBreakdownParser:
    def __init__(self):
        pass

    def parse(self, _iter, instance):
        line = _iter.next()
        if line.startswith("*total"):
            h = Heap()
            while(len(instance.context) != 0) :
                i = instance.context.popleft().split()
                inst = Instruction(*i)
                h.add(inst)
            instance.state = instance.outsideblock_parser
            instance.output[instance.last_state_transition_input] = h
            instance.last_state_transition_input = None
            instance.context.clear()
        else:
            if(not line.startswith("*") and not line.startswith("#")):
                instance.context.append(line.strip())

class SdeReportParser:

    def __init__(self, inblock_parser, outsideblock_parser):
        self.inblock_parser = inblock_parser
        self.outsideblock_parser = outsideblock_parser
        self.state = self.outsideblock_parser
        self.last_state_transition_input = None
        self.context = deque()
        self._output = OrderedDict()

    def parse(self, _iter):
        self.state.parse(_iter, self)

    @property
    def output(self):
        return self._output
    
    @output.setter
    def output(self, value):
        self._output = value

def extract_instructions_count(file_path):
    """
    Parses instructions count for all functions in the report
    """
    parser = SdeReportParser(InsideFunctionAssemblyBreakdownParser(),
                             OutsideFunctionAssemblyBreakdownParser())
    try:
        with open(file_path) as f:
            while True:
                try:
                    parser.parse(f)
                except StopIteration:
                    break
    except IOError as e:
        sys.stdout.write("Error while reading SDE report: {}".format(e))
        sys.exit(1)
    return parser.output

class OutsideFunctionListParser:
    def __init__(self):
        pass
    def parse(self, _iter, instance):
        line = _iter.next()
        if(line.startswith("# FUNCTION TOTALS")):
            instance.state = instance.inblock_parser

class InsideFunctionListParser:
    def __init__(self):
        pass

    def parse(self, _iter, instance):
        line = _iter.next()
        if line.startswith("#"):
            return
        elif line == "# END FUNCTION TOTALS":
            raise StopIteration
        elif re.search(r"^\s*\d+:", line) != None:
            fields = line.split()
            num = fields[0].strip()[:-2]
            weight, module, func =  fields[2], fields[6], fields[8]
            instance.output[(func, module, "{} %".format(weight))] = num

def extract_functions_list(file_path):
    """
    Returns a summary of the functions executed by the two executables
    """
    parser = SdeReportParser(InsideFunctionListParser(), OutsideFunctionListParser())
    try:
        with open(file_path) as f:
            while True:
                try:
                    parser.parse(f)
                except StopIteration:
                    break
    except IOError as e:
        sys.stdout.write("Error while reading SDE report: {}".format(e))
        sys.exit(1)
    # The output of the parsers is an OrderedDict, turn into a deque
    return deque(parser.output.keys())


class InstructionCompareBackend(object):
    def __init__(self):
        # A list of tuples (el0, el1, el3), corresponding respectively to
        # instruction name, instruction count exec 1, instruction count exec 2
        self.data = list()
        pass

    def feed(self):
        while(True):
            r = yield
            self.data.append(r)
        pass

class StdoutBackend(InstructionCompareBackend):
    def __init__(self):
       super(StdoutBackend, self).__init__()

    def render(self, label1, label2, func, module):
        headers = ["opcode", label1, label2]
        sys.stdout.write("{} in {}".format(func, module))
        sys.stdout.write(tabulate.tabulate(self.data, headers = headers))

class GraphBackend(InstructionCompareBackend):

    def __init__(self):
        super(GraphBackend, self).__init__()

    def render(self, label1, label2, func, module):
        width = 0.4
        position = np.arange(len(self.data))
        plt.figure(figsize=(10, 5))
        ax = plt.axes()
        ax.set_xticks(position + width)
        ax.set_xticklabels( [el[0] for el in self.data] , rotation = 90)
        plt.yscale('log', nonposy='clip')
        plt.bar(position,
                [int(el[1]) for el in self.data] ,
                width,
                alpha = 0.5,
                color='b',
                label = label1)
        plt.bar(position + width,
                [int(el[2]) for el in self.data] ,
                width,
                alpha = 0.5,
                color='r',
                label = label2)
        plt.legend()
        plt.tight_layout(pad = 1)
        plt.title("{} in {}".format(func,module))
        plt.yscale('log', nonposy='clip')
        plt.grid()

class GraphShowBackend(GraphBackend): 

    def show(self):
        plt.show()

    def render(self, label1, label2, func, module):
        super(GraphShowBackend, self). render(label1, label2, func, module)
        self.show()

class GraphSaveBackend(GraphBackend):

    def save(self, func):
        plt.savefig("{}.png".format(func), dpi = 600)
 
    def render(self, label1, label2, func, module):
        super(GraphSaveBackend, self). render(label1, label2, func, module)
        self.save(func)

def compare_instructions_count(first, second, func, module, backend):
    """
    Compares the instructions count in function func between the first and
    second executable. Prints the comparison keeping instructions in order
    (higher count to lower count).
    Args:
        backend: The backend responsible for rendering the data. Can be
                 an stdout based backend of a matplot lib based on. backend
                 is a generator.
    """
    backend.next()
    raised = 0
    try:
        h1 = first[(func, module)]
    except KeyError:
        raised += 1
        h1 = Heap()
    try:
        h2 = second[(func, module)]
    except KeyError:
        raised += 1
        h2 = Heap()

    if(raised == 2):
        raise Exception("function {} does not exist".format(func))

    i1 = h1.pop()
    i2 = h2.pop()

    # If instructions do not appear in the same order in the heaps, then
    # try popping out of order to avoid duplicated entries associated with 0.
    while(i1 != None and i2 != None):
        if(i1 == i2):
            t = (i1.opcode(), i1.count(), i2.count())
            backend.send(t)
            i1 = h1.pop()
            i2 = h2.pop()
        # Instructions are ordered differently. Consider the instruction with the
        # highest count and try to pop from the other heap out of order.
        elif(i1.count() > i2.count()):
            try:
                i2_out_of_order = h2.pop_out_of_order(i1)
                t = (i1.opcode(), i1.count(), i2_out_of_order.count())
            except Exception, e:
                t = (i1.opcode(), i1.count(), "0")
            backend.send(t)
            i1 = h1.pop()
        else:
            try:
                i1_out_of_order = h1.pop_out_of_order(i2)
                t = (i1_out_of_order.opcode(), i1_out_of_order.count(), i2.count())
            except Exception, e:
                t = (i2.opcode(), "0", i2.count())
            backend.send(t)
            i2 = h2.pop()

    while(i1 != None):
        t = (i1.opcode(), i1.count(), "0")
        backend.send(t)
        i1 = h1.pop()

    while(i2 != None):
        t = (i2.opcode(), "0", i2.count())
        backend.send(t)
        i2 = h2.pop()


def compare_functions_list(first, second):
    aggregate = list()
    while(len(first) != 0 and len(second) != 0):
        aggregate.append(list(first.popleft()) + list(second.popleft()))

    while(len(first) != 0):
        aggregate.append(list(first.popleft()) + ["", "", ""])
    while(len(second) != 0):
        aggregate.append(["", "", ""] + list(second.popleft()))

    headers=["Function 1", "Module 1", "Runtime 1",
             "Function 2", "Module 2", "Runtime 2", ]
    sys.stdout.write(tabulate.tabulate(aggregate, headers))
    sys.stdout.write("\n")

if __name__ == '__main__':

    options, parser = cmdline()
    if(options.first == None):
        sys.stdout.write("Path of first report not provided\n")
        sys.exit(1)
    if(options.second == None):
        sys.stdout.write("Path of second report not provided\n")
        sys.exit(1)
    if(options.func == None and options.list == False):
        sys.stdout.write("Function name to produce the report for not specified\n")
        sys.exit(1)
    try:
        if(options.list):
            first = extract_functions_list(options.first)
            second = extract_functions_list(options.second)
            compare_functions_list(first, second)
        else:
            label1 = options.labels.split(",")[0]
            label2 = options.labels.split(",")[1]
            first = extract_instructions_count(options.first)
            second = extract_instructions_count(options.second)
            func = options.func
            # Check if there are multiple occurrences of func. If so, ask
            # which one to consider
            occurrences = filter(lambda x: x[0] == func, first)
            occurrences += filter(lambda x: x[0] == func, second)
            occurrences = set(occurrences)
            if(len(occurrences) == 0):
                raise Exception("function {} not found".format(func))
            if(len(occurrences) > 1):
                sys.stdout.write("Multiple occurrences of {} found\n".format(func))
                sys.stdout.write("Please choose one:\n")
                choice = -1
                while(choice < 0 or choice > len(occurrences)):
                    for n, t in enumerate(occurrences):
                        sys.stdout.write("{}: {} in {}\n".format(n, t[0], t[1]) )
                    try:
                        choice = int(sys.stdin.readline())
                    except Exception, e:
                        choice = -1
                func, module = list(occurrences)[choice]
            else:
                func, module = list(occurrences)[0]

            if(options.graph):
                if(options.save):
                    backend = GraphSaveBackend()
                else:
                    backend = GraphShowBackend()
            else:
                backend = StdoutBackend()

            compare_instructions_count(first, second, func, module, backend.feed())
            backend.render(label1, label2, func, module)
    except Exception, e:
        sys.stderr.write("Error: {}".format(e))
        sys.stderr.write("Exception: {}".format(get_exception_info()))
