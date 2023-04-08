#Authors:
# Sayandeep Sen (sayandes@in.ibm.com)
# Palani Kodeswaran (palani@in.ibm.com)

import re
import os
import json
import argparse
import subprocess
import shutil
from collections import defaultdict
from tinydb import TinyDB
import utils.comment_extractor as extractor
import handle_c_style_comments as rmc

def run_cmd(cmd):
    status, output = subprocess.getstatusoutput(cmd)
    if(status != 0):
        print("Running: ",cmd)
        print("Failed while running: ",cmd,"Message: ",output, " Exiting...")
        exit(1)
    return output

def get_read_maps(lines, map_read_fn):
    map_read_set=set()
    for line in lines:
        mapname= check_map_access(map_read_fn,line)
        if mapname != None:
            map_read_set.add(mapname)
    return list(map_read_set)

def get_update_maps(lines, map_update_fn):
    map_update_set=set()
    for line in lines:
        mapname= check_map_access(map_update_fn,line)
        if mapname != None:
            map_update_set.add(mapname)
    return list(map_update_set)

def create_capability_dict(helper_list, helperdict):
    cap_dict = {}
    for fn in helper_list:
        for cap in helperdict[fn]['capabilities']:
            if cap not in cap_dict:
                cap_dict[cap] = list()
            cap_dict[cap].append(fn)

    data_list = []
    for cap_name in cap_dict.keys():
        data = {}
        data["capability"] = cap_name
        lst = []
        for helper in cap_dict[cap_name]:
            #print("got "+helper+"->")#+str(manpage_info_dict[helper]["Function Name"]))
            lst.append(helperdict[helper])
        data[cap_name]=lst
        data_list.append(data)
    return data_list

def add_dict_to_cap_dict(cap_dict, cap_name):
    if  not (cap_name in cap_dict):
        cap_dict[cap_name] = {}
        
def add_helper_to_dict(cap_dict,cap_name,helper_name):
    try:
        helper_dict = cap_dict[cap_name]
        helper_dict[helper_name] = 1
    except Exception as e:
        print(e)

def generate_capabilities(helper_list,cap_dict):
    capabilities = {}
    #print("Capabilities")
    for cap_name in cap_dict.keys():
        helpers=set()
        #print(cap_name)
        cap_helpers = cap_dict[cap_name]
        #print("cap_helpers")
        #print(cap_helpers)
        for helper_name in helper_list:
            #print(helper_name)
            if helper_name in cap_helpers.keys():
                #print("Adding: "+cap_name)
                helpers.add(helper_name)
        if len(helpers) > 0:
            #capabilities[cap_name]=set_to_string(helpers)
            capabilities[cap_name] = helpers
    return capabilities

def get_compatible_hookpoints(helpers,helper_hookpoint_dict):
    hook_set = None
    if helpers is None or len(helpers) == 0:
        hook_set = get_all_available_hookpoints(helper_hookpoint_dict)
        #print("Helpers None: ")
        #print(hook_set)
        return list(hook_set)
        #return ["All_hookpoints"]
    
    for helper in set(helpers):
        if 'compatible_hookpoints' not in helper_hookpoint_dict[helper]:
            continue

        helper_set = set(helper_hookpoint_dict[helper]["compatible_hookpoints"])
        if hook_set == None:
            hook_set = helper_set
        else:
            hook_set = hook_set.intersection(helper_set)
    if hook_set is None:
        return None
    return list(hook_set)


def decompile(prog_file):
    lines = []
    cmd = "bpftool prog dump xlated pinned " + prog_file + " > temp.c"
    output = run_cmd(cmd)

    #remove ; from bpftool output
    cmd = "grep \";\" temp.c > dumped.c"
    # check bpftool version. some verions dont have ";"
    #output = run_cmd(cmd)
    #open dumped.c
    dumped_file = open("dumped.c",'r')

    for line in dumped_file.readlines():
        print(line)
    return lines

def load_bpf_helper_cap(fname):
    data = {}
    try:
        with open(fname, 'r') as f:
            data = json.load(f)
    except IOError as e:
        print("Could not open file: "+fname)
    return data


def load_bpf_helper_map(fname):
    print("Filename: "+fname)
    data = []
    ret = {}
    try:
        with open(fname, 'r') as f:
            data = json.load(f)
    except IOError as e:
        print("Could not open file: "+fname)
    for entry in data:
        #print("This is entry: "+entry)
        keys = entry.keys()
        for keys in entry:
            ret[keys] = entry[keys]
    return ret

def check_and_return_func_present(helperdict, line):
    hls =  list()
    for helper in helperdict.keys():
        if line.find(helper)>=0 :
            if line.find('bpf_'+helper) >= 0:
                continue
            hls.append(helper)
    return hls

def get_helper_list(lines,helperdict):
    helper_set= set()
    for line in lines:
        present= check_and_return_func_present(helperdict,line)
        if present != None:
            helper_set.update(present)
    return list(helper_set)

def get_prog_id(sec_name,output):
    lines = output.split("\n")
    #print(lines)
    last_line=""
    for line in lines:
        if sec_name in line:
            print(line)
            last_line = line
    #print("Get prog_id: ",last_line)
    prog_id = last_line.split(":")[0]
    print(prog_id)
    return prog_id

def check_map_access(my_arr,line):
    for func in my_arr:
        idx = line.find(func)
        if idx>=0:
            chunks = line[len(func)+idx:].replace('(','')
            first_entry_end = chunks.find(',')
            return chunks[:first_entry_end].replace("&","")
    return None


def run_cmd(cmd):
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True) as process:
        output = process.communicate()[0].decode("utf-8")
        #print(output)
        return output

def remove_line_comments(lines):
    lines = "".join(lines)
    lines = rmc.removeComments(lines)
    lines = lines.replace("}","").replace("{",";").replace("\n","")
    return lines.split(";")
    
def get_capability_dict(code_lines, helperdict):
    code_lines = remove_line_comments(code_lines)
    helperCallParams = defaultdict(list)
    helpers_list = get_helper_list(code_lines, helperdict)
    op_dict = {}
    op_dict["capabilities"] = create_capability_dict(helpers_list, helperdict)
    op_dict["helperCallParams"] = helperCallParams
    return op_dict


def get_all_available_hookpoints(helper_hookpoint_dict):
    hookpoint_set = set()
    for info_str in helper_hookpoint_dict.values():
        if info_str is None or "compatible_hookpoints" not in info_str:
            continue
        hookpoint_set.update(info_str["compatible_hookpoints"])
    return list(hookpoint_set)

def dump_comment(fname,startLineDict, ofname):
    if fname  == "":
        return
    ifile = open(fname,'r')
    ofile = open(ofname,'w')
    ct = 0
    for line in ifile.readlines():
        ct=ct + 1
        if ct in startLineDict:
            ofile.write(startLineDict.get(ct))    
        ofile.write(line)
    ofile.flush()
    ofile.close()
    ifile.close()


def get_called_fn_list(fn_name, db_file_name, manpage_info_dict):
    fn_name_s = fn_name.replace("*","")
    fn_name_s = fn_name.replace("&","")
    cmd = "cqsearch -s "+ db_file_name+" -t "+ fn_name_s +"  -p 7  -u -e"
    op = run_cmd(cmd).split("\n")
    called_fn_dict = set()
    for en in op:
        if "Search string:" not in en:
            fn_det_list = en.split("\t")
            func = fn_det_list[0].replace("*","")
            if func not in manpage_info_dict and func != "DECLARE":
                called_fn_dict.add(func)
    return list(called_fn_dict)

def generate_comment(capability_dict):
    return "/* \n OPENED COMMENT BEGIN \n"+json.dumps(capability_dict,indent=2)+" \n OPENED COMMENT END \n */ \n"


# parses output from c-extract-function.txl
def parseTXLFunctionOutputFileForComments(txlFile, opFile, srcFile, helperdict, map_update_fn, map_read_fn, human_comments_file, db_file_name, funcCapDict):
    srcSeen=False
    lines = []
    startLineDict ={}
    funcName=""
    funcArgs=""
    output=""
    startLine = -1
    endLine = -1
    prevEndLine = 0

    ifile = open(srcFile,'r')
    srcLineList = ifile.readlines()
    ifile.close()


    for line in txlFile.readlines():
        ending = re.match(r"</source",line)
        if ending:
            srcSeen = False
            #dump to file
            funcName = funcName.replace('*','')
            capability_dict = get_capability_dict(srcLineList[startLine:endLine], helperdict)
            capability_dict['startLine'] = startLine
            capability_dict['endLine'] = endLine
            capability_dict['File'] = srcFile
            capability_dict['funcName'] = funcName
            capability_dict['developer_inline_comments'] = rmc.find_c_style_comment_matches_in_func(''.join(srcLineList[prevEndLine:endLine]), prevEndLine)
            prevEndLine = endLine + 1
            capability_dict['updateMaps'] = get_update_maps(lines, map_update_fn)
            capability_dict['readMaps'] = get_read_maps(lines, map_read_fn)
            capability_dict['input'] = funcArgs.split(',')
            capability_dict['output'] = output
            capability_dict['helper'] = get_helper_list(lines, helperdict)
            capability_dict['compatibleHookpoints'] = get_compatible_hookpoints(capability_dict['helper'] , helperdict)
            capability_dict['source'] = lines
            capability_dict['called_function_list'] = get_called_fn_list(funcName, db_file_name, helperdict)
            if capability_dict['called_function_list'] is not None and not len(capability_dict['called_function_list']):
                capability_dict["call_depth"] =  0
            else:
                capability_dict["call_depth"] = -1

            func_desc_list = []
            human_description = extractor.get_human_func_description(human_comments_file,srcFile,funcName)
            empty_desc = {}
            empty_desc['description'] = ""
            empty_desc['author'] = ""
            empty_desc['authorEmail'] = ""
            empty_desc['date'] = ""

            func_desc_list.append(human_description)
            capability_dict['humanFuncDescription'] = func_desc_list
            empty_desc_auto = {}
            empty_desc_auto['description'] = ""
            empty_desc_auto['author'] = ""
            empty_desc_auto['authorEmail'] = ""
            empty_desc_auto['date'] = ""
            empty_desc_auto['invocationParameters'] = ""
            ai_func_desc_list = []
            ai_func_desc_list.append(empty_desc_auto)
            capability_dict['AI_func_description'] = ai_func_desc_list
            comment = generate_comment(capability_dict)
            #insert_to_db(comments_db,capability_dict)
            if funcName not in funcCapDict:
                funcCapDict[funcName] = list()
            funcCapDict[funcName].append(capability_dict)
            
            startLineDict[startLine] = comment
            lines = []
            continue
        if srcSeen:
            lines.append(line)
            continue
        starting = re.match(r"<source",line)
        if starting:
            srcSeen = True
        
            line = line.replace("funcheader","")
            line = line.replace("startline","")
            line = line.replace("endline","")
            line = line.replace(">","")
            line = line.replace("\n","")
            line = line.replace("\"","")
            tokens = line.split('=')

            funcHeader=tokens[2]
            funcArgs = funcHeader.split('(')[-1]
            funcArgs = funcArgs.split(')')[0]
            if(funcArgs is None or not funcArgs or funcArgs.isspace() is True):
                funcArgs = "NA"

            srcFile = tokens[-4]
            srcFile = srcFile.replace(" ","")

            funcName = tokens[-3].replace(" (","(")
            output= " ".join(funcName.split('(')[-2].split(" ")[:-1])
            output = output.replace(" ","")
            if(output is None or not output or output.isspace() is True):
                output = "NA"
            funcName = funcName.split('(')[-2].split(" ")[-1]

            startLine = int(tokens[-2])
            endLine = int(tokens[-1])
    if srcFile != "":
        dump_comment(srcFile, startLineDict, opFile)
    return funcCapDict
