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
import glob
import numpy  as np
import pandas as pd

critical_processes = [
    'System', 'smss.exe', 'wininit.exe', 'RuntimeBroker.exe', 'taskhostw.exe', 'winlogon.exe', 
    'csrss.exe', 'services.exe', 'svchost.exe', 'lsaiso.exe', 'lsass.exe', 'explorer.exe']

boot_start_processes = [
    'System', 'smss.exe', 'wininit.exe', 'winlogon.exe', 'csrss.exe', 'services.exe', 'lsaiso.exe', 
    'lsass.exe' ]

process_parents = pd.DataFrame([
    ['System', ''],
    ['smss.exe', 'System'],
    ['wininit.exe', 'smss.exe'],
    ['RuntimeBroker.exe', 'svchost.exe'],
    ['taskhostw.exe', 'svchost.exe'],
    ['winlogon.exe', 'smss.exe'],
    ['csrss.exe', 'smss.exe'],
    ['services.exe', 'wininit.exe'],
    ['svchost.exe', 'services.exe'],
    ['lsaiso.exe', 'wininit.exe'],
    ['lsass.exe', 'wininit.exe'],
    ['explorer.exe', 'userinit.exe']],
    columns=['Child', 'Parent'])

def read_volatility(evd, prefix, ext):
    """ Read volatility files from a directory and put in a pandas Dataframe for analysis

    Parameters:
    evd (str): Path of volatilty files
    prefix (str): Get files with this prefix
    ext (str): Get files with this extension
    
    Returns:
    pd.DataFrame: Contains volatility files info.
                  You can use the syntax <yourvar>['Category'] to access your dataframe

    """
    dfs = {}
    volfsf = [f for f in glob.glob(evd + "/*/*" + ext)]
    # TODO: Use regex to include "^" & "$" instead of a vanilla replace
    cats = [os.path.basename(volff).replace(prefix, '').replace(ext, '') for volff in volfsf]
    cats = np.unique(cats)
    for cat in cats:
            dfs[cat] = pd.DataFrame()
            print('Reading csv files for category %-20s into dataframe ->  %-20s' % (cat, cat))
            hostcatfs = [f for f in glob.glob(evd+"/*/" + prefix + cat + ext)]
            for hostcatf in hostcatfs:
                hostdfull = os.path.dirname(hostcatf)
                host = os.path.basename(hostdfull)
                try:
                    hostcatlines = pd.read_csv(hostcatf,sep="|")
                except:                
                    hostcatlines = pd.DataFrame()    
                hostcatlines.insert(0,'Hostname',host)
                if cat == "pslist":
                    hostcatlines['Start'] = pd.to_datetime(hostcatlines['Start'])
                    hostcatlines['PID'] = hostcatlines['PID'].astype('int64')
                    hostcatlines['PPID'] = hostcatlines['PPID'].astype('int64')
                    hostcatlines['Thds'] = hostcatlines['Thds'].astype('int64')
                    hostcatlines['Hnds'] = hostcatlines['Hnds'].astype('int64')
                    hostcatlines['Sess'] = hostcatlines['Sess'].astype('int64')
                    hostcatlines['Wow64'] = hostcatlines['Wow64'].astype('int64')
                    hostcatlines['Exit'] = pd.to_datetime(hostcatlines['Exit'])
                dfs[cat] = pd.concat([dfs[cat], hostcatlines], ignore_index=True)
    print("\n\nNOTE: Now you can use the syntax <yourvar>['Category'] to access your dataframe")
    return dfs

def volatility_pslist_boot_time_anomaly_analysis(pslistdf, secs=30):
    """ Find anomalies in boot time

    Parameters:
    pslistdf (pd.DataFrame): Dataframe with pslist volatility info
    secs (int): Diference of boot time
    
    Returns:
    pd.DataFrame: Analysis results, processes that have an anomalous boottime

    """
    bootps = pslistdf[pslistdf['Name'].isin(boot_start_processes)  & (pslistdf['Sess'] <= 1) & pslistdf['Exit'].isnull() ]
    return bootps[bootps['Start'] >= bootps['Start'].min() + pd.Timedelta(seconds=secs)]


def volatility_processes_parent_analysis(pslistdf, critical_only=False):
    """ Find anomalies in parent processes

    Parameters:
    pslistdf (pd.DataFrame): Dataframe with pslist volatility info
    critical_only (bool): Only critical process
    
    Returns:
    None
    """
    pslistdf_alive = pslistdf[pslistdf['Exit'].isna()]
    hnpid = pslistdf_alive[['Hostname', 'Name', 'PID']]
    hnppid = pslistdf_alive[['Hostname', 'Name', 'PPID']]
    family = pd.merge(
                    hnppid, hnpid, left_on=['Hostname', 'PPID'], right_on=['Hostname', 'PID'], how='left'
              ).dropna(
              ).drop(
                    columns=['Hostname', 'PPID', 'PID']
              ).rename(
                    columns={'Name_x': 'Child', 'Name_y': 'Parent'}
              ).reset_index(
              ).drop(
                    columns=['index'])
    if critical_only:
        thisfamily = family.query('Child == @critical_processes')
    else:
        thisfamily = family
    family_unknown = pd.merge(
                            thisfamily,process_parents, indicator=True, how='outer'
                      ).query(
                            '_merge=="left_only"'
                      ).drop(
                            '_merge', axis=1)
    print(family_unknown.groupby(["Child", "Parent"]).size().sort_values(ascending=False))


def cmd_volatility_pslist_boot_time_anomaly_analysis(args):
    dfss = read_volatility(args.volatility_path, args.prefix, args.ext)
    pslistdf=dfss['pslist']
    results = volatility_pslist_boot_time_anomaly_analysis(pslistdf, secs=args.secs)
    print(results)

def cmd_volatility_processes_parent_analysis(args):
    print("READING VOLATILITY FILES...")
    dfss = read_volatility(args.volatility_path, args.prefix, args.ext)
    pslistdf=dfss['pslist']
    print()
    print("ANALYSIS RESULTS:")
    volatility_processes_parent_analysis(pslistdf, critical_only=args.critical)
    

if __name__ == "__main__":
    pd.set_option('display.max_columns', None)  
    pd.set_option('display.expand_frame_repr', False)
    pd.set_option('max_colwidth', None)
    
    parser = argparse.ArgumentParser("DS4N6 FileSystem Timeline Analysis Script")
    subparsers = parser.add_subparsers()
    
    cmd_volatility_pslist_boot_time_anomaly_analysis_parser = subparsers.add_parser('pslist_boot_time_anomaly_analysis', help="Find anomalies in boot time")
    cmd_volatility_pslist_boot_time_anomaly_analysis_parser.add_argument("volatility_path", type=str, help='Path of volatilty files')
    cmd_volatility_pslist_boot_time_anomaly_analysis_parser.add_argument("prefix", type=str, help='Get files with this prefix')
    cmd_volatility_pslist_boot_time_anomaly_analysis_parser.add_argument("ext", type=str, help='Get files with this extension')
    cmd_volatility_pslist_boot_time_anomaly_analysis_parser.add_argument("-s", "--secs", type=int, default=30, help='diference of boot time' )
    cmd_volatility_pslist_boot_time_anomaly_analysis_parser.set_defaults(func=cmd_volatility_pslist_boot_time_anomaly_analysis)

    cmd_volatility_processes_parent_analysis_parser = subparsers.add_parser('processes_parent_analysis', help="Find anomalies in parent processes")
    cmd_volatility_processes_parent_analysis_parser.add_argument("volatility_path", type=str, help='Path of volatilty files')
    cmd_volatility_processes_parent_analysis_parser.add_argument("prefix", type=str, help='Get files with this prefix')
    cmd_volatility_processes_parent_analysis_parser.add_argument("ext", type=str, help='Get files with this extension')
    cmd_volatility_processes_parent_analysis_parser.add_argument("-c", "--critical", action="store_true", help='Critical processes only')
    cmd_volatility_processes_parent_analysis_parser.set_defaults(func=cmd_volatility_processes_parent_analysis)
    
    args = parser.parse_args()
    try:
        args.func(args)
    except AttributeError:
        parser.print_help()
        print()
        print(80 * "-")
        print("Command: pslist_boot_time_anomaly_analysis - Find anomalies in parent processes")
        print(80 * "-")
        cmd_volatility_pslist_boot_time_anomaly_analysis_parser.print_help()
        print()
        print(80 * "-")
        print("Command: processes_parent_analysis - Find anomalies in parent processes")
        print(80 * "-")
        cmd_volatility_processes_parent_analysis_parser.print_help()
        parser.exit()
