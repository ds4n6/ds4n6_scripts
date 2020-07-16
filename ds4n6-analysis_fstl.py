#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__copyright__ = "Copyright 2020, DS4N6 Project"
__credits__ = ["Jess Garcia"]
__license__ = "GPL"
__version__ = "1.0.1"
__maintainer__ = "Jess Garcia"
__email__ = "ds4n6@one-esecurity.com"
"""

import argparse
import os
import time

import pandas as pd


def read_fstl(fstlf, windows=False):
    fstl = pd.read_csv(fstlf)
    fstl['Date'] = fstl['Date'].astype('datetime64')
    fstl = fstl.rename(columns={"File Name": "FileName"})
    if windows:
        fstl.drop(columns=['Mode','UID','GID'],inplace=True)
    return fstl


def fstl_size_top_n(fstl, n):
    return fstl[~fstl['FileName'].str.contains("\(\$FILE_NAME\)")][['Size','FileName']].sort_values(by='Size', ascending=False).drop_duplicates().head(n)


def cmd_fstl_size_top_n(args):
    fstl = read_fstl(args.fstl_file, windows=args.windows)
    results = fstl_size_top_n(fstl,args.n)
    print(results)

def read_fstls_filetypes(fstld, hosts, file_types, verbose=False):
    fstl_names = ['1', 'path', 'inode', 'perms', 'user', 'group', 'fsize', 'mtime', 'atime', 'ctime', 'btime']
    fstl_hostname_names = ['host-vol', '1', 'path', 'inode', 'perms', 'user', 'group', 'fsize', 'mtime', 'atime', 'ctime', 'btime']
    fstl_hostname_names_short = ['host-vol', 'path', 'inode', 'fsize', 'mtime', 'atime', 'ctime', 'btime']

    # Initialize dictionary of dfs
    dfs = {}
    for file_type in file_types:
        dfs[file_type] = pd.DataFrame(columns = fstl_hostname_names_short)

    nhosts = len(hosts)

    if verbose:
        print("No. Hosts: "+str(nhosts))
        print("- Reading files:")

    start_time = time.time()

    cnt = 1
    for host in hosts:
        fstlf = fstld + "/" + host + "/fstlmaster.body.raw"
        os.system("ls -l " + fstlf + " | sed 's:" + fstld + "/::' | awk '{ print \"      \" $0 }'")

        filename=fstlf
        if verbose:
            print("  + [" + str(cnt) + "/" + str(nhosts) + "] Reading file: " + filename)
        dirname = os.path.dirname(filename)
        dirnamebase = os.path.basename(dirname)
        parse_dates = ['mtime', 'atime','ctime']
        fstlraw = pd.read_csv(filename, sep='|', names=fstl_names, parse_dates=parse_dates, date_parser=lambda col: pd.to_datetime(col, unit="s"))
        fstlraw.insert(0,'host-vol',dirnamebase)

        # Remove meaningless cols -------------------------------
        # Delete first col
        del fstlraw['1']
        # Delete Meaningless Windows cols
        del fstlraw['perms']
        del fstlraw['user']
        del fstlraw['group']
        # Add path-hash col
        fstlraw.insert(2,'path-hash',0)
        fstlraw['path-hash'] = fstlraw['path'].str.lower().apply(hash)

        thisdfs={}
        for file_type in file_types:
            thisdfs[file_type] = fstlraw[fstlraw['path'].str.contains("."+file_type+"$")]
            dfs[file_type] = pd.concat([dfs[file_type], thisdfs[file_type]])

        if verbose:
            print("    - No.lines fstls:   " + str(fstlraw.path.size))
            for file_type in file_types:
                print("    - No.lines " + file_type + ":     " + str(thisdfs[file_type].path.size))
                print("    - No.lines " + file_type + " acc: " + str(dfs[file_type].path.size))
        else:
            if verbose:
                print(".", end='')
            if ( cnt % 10 == 0 ):
                print("[" + str(cnt) + "]", end='')
        cnt = cnt + 1

    if verbose:
        print("- "+str(nhosts)+" files read")
        print("- Creating Low-Res TStamp versions of DFs")

    for file_type in file_types:
        dfs[file_type]=dfs[file_type].astype(
            {
                'path-hash': 'int64', 
                'mtime': 'datetime64[s]', 
                'atime': 'datetime64[s]', 
                'ctime': 'datetime64[s]', 
                'btime': 'datetime64[s]'})

    elapsed_time = time.time() - start_time
    if verbose:
        print("- Elapsed time: "+str(elapsed_time))

    return dfs

def unique_files_folder_analysis(exefs, thisexed_path, exef_intg_max_occs, compop='==', recurse=False, prevdays=0, tsfield='m', verbose=False):
    # TODO:
    # - Include "recurse" option so the sub-folders can be included or excluded

    if compop not in ['>', '<', '>=', '==', '<=']:
        print("Invalid Comparison Operator: "+compop)
        return False

    regexrec=thisexed_path+"/"
    regexnorec=thisexed_path+"/[^/]*$"

    if recurse == True:
        thisexefsrec=exefs[exefs['path'].str.contains(regexrec,case=False,regex=True)]
        nexefsrec=len(thisexefsrec)
        thisexefs=thisexefsrec
        if verbose == True:
            print("No. files (recursive):     "+str(nexefsrec)+"\n")
    else:
        thisexefsnorec=exefs[exefs['path'].str.contains(regexnorec,case=False,regex=True)]
        nexefsnorec=len(thisexefsnorec)
        thisexefs=thisexefsnorec
        if verbose == True:
            print("No. files (non-recursive): "+str(nexefsnorec)+"\n")

    exefgrps = thisexefs.groupby('path-hash')
    exefgrps_groups = exefgrps.groups
    nexefgrps = len(exefgrps_groups)
    exef_sizes=exefgrps.groups.keys()
    exef_sizes_occs=exefgrps.size()
    if verbose:
        print("phash ANALYSIS - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n")
        print("RECURSION: "+str(recurse))
        print("No.groups: "+str(nexefgrps)+"\n")

    if prevdays == 0 :
        exef_intg = exefgrps.filter(lambda x: eval( str(len(x)) + compop + str(exef_intg_max_occs)) )
    else:
        print("No. Interesting (no. occurrences <=" + str(exef_intg_max_occs) + "): " + str(nexef_intg) + "\n")
        lastmtime = exef_intg.sort_values(by="mtime").tail(1)['mtime']
        print("Last mtime: " + str(lastmtime))
        prevdate = lastmtime + pd.DateOffset(days=-prevdays)
        print("Previous Date: "+  str(prevdate))

    return exef_intg

def cmd_unique_files_folder_analysis(args):
    hosts = os.listdir(args.fstl_hosts_directory)
    fsdf = read_fstls_filetypes(args.fstl_hosts_directory, hosts, ['exe'], verbose=args.verbose)
    results = unique_files_folder_analysis(fsdf['exe'], args.analysis_path, args.ocurrences, compop=args.compop, verbose=args.verbose)  
    print(results)

if __name__ == "__main__":
    pd.set_option('display.max_columns', None)  
    pd.set_option('display.expand_frame_repr', False)
    pd.set_option('max_colwidth', None)
    
    parser = argparse.ArgumentParser("DS4N6 FileSystem Timeline Analysis Script")
    subparsers = parser.add_subparsers()
    
    cmd_fstl_size_top_n_parser = subparsers.add_parser('fstl_size_top_n', help="Get top n max size files")
    cmd_fstl_size_top_n_parser.add_argument("fstl_file", type=str, help='FSTL file')
    cmd_fstl_size_top_n_parser.add_argument("n", type=int, help='Number of desired results' )
    cmd_fstl_size_top_n_parser.add_argument("-w", "--windows", action="store_true", help='The FSTL file is from windows hosts' )
    cmd_fstl_size_top_n_parser.set_defaults(func=cmd_fstl_size_top_n)

    cmd_unique_files_folder_analysis_parser = subparsers.add_parser('unique_files_folder_analysis', help="Get exe files found with a number of occurrences in systems")
    cmd_unique_files_folder_analysis_parser.add_argument("fstl_hosts_directory", type=str, help='directory wiht host folders that contains fstl files')
    cmd_unique_files_folder_analysis_parser.add_argument("analysis_path", type=str, help='Path to analyze (eg: windows/system32)')
    cmd_unique_files_folder_analysis_parser.add_argument("ocurrences", type=int, help='ocurrences of a file')
    cmd_unique_files_folder_analysis_parser.add_argument("-c", "--compop", type=str, default="<=", help='Compare ocurrences: < | > | == | >= | <=  (default: <=)')
    cmd_unique_files_folder_analysis_parser.add_argument("-v", "--verbose", action="store_true", help='shows more info')

    cmd_unique_files_folder_analysis_parser.set_defaults(func=cmd_unique_files_folder_analysis)
    
    args = parser.parse_args()
    try:
        args.func(args)
    except AttributeError:
        parser.print_help()
        print()
        print(80 * "-")
        print("    Command: fstl_size_top_n - Get top n max size files")
        print(80 * "-")
        cmd_fstl_size_top_n_parser.print_help()
        print()
        print(80 * "-")
        print("    Command: unique_files_folder_analysis - Get exe files found with a number of occurrences in systems")
        print(80 * "-")

        cmd_unique_files_folder_analysis_parser.print_help()
        parser.exit()
    