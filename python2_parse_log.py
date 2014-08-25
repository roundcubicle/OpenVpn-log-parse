#!/usr/bin/env python2
#C:\Python27

__date__ = "08/17/2014"
__author__ = "AlienOne"
__copyright__ = "MIT"
__credits__ = ["Justin Jessup"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "AlienOne"
__email__ = "Justin@alienonesecurity.com"
__status__ = "Development Testing"


"""
Description:
    Parse log file for LDAP data type - parses @ 1:38 per GB - event size 303 bytes - 37555/EPS

Usage:
    python2 python2_parser.py
"""


import csv
import fnmatch
import os
import re


def recursive_search(root_path, regex):
    """
        Recursively search a directory tree

    Args:
        root_path: The root from which the search is initiated
        regex: Regular expression of files to search for

    Returns:
        Generator object consisting of full path to filename
    """
    for root, dirs, files in os.walk(root_path):
        for filename in fnmatch.filter(files, regex):
            yield os.path.join(root, filename)


def parse_file(root_path, path_regex, parser_regex):
    """
        Parse log file utilizing regular expression matching

    Args:
        root_path: The root from which the search is initiated
        path_regex: Regular expression of files to search for
        parser_regex: Regular expression to parse log file into value tokens
        buffering: 1GB memory dedicated to file chunk reading

    Returns:
        Generator dictionary object, index keys, to tokenized values
    """
    pattern = re.compile(parser_regex)
    for filename in recursive_search(root_path, path_regex):
        with open(filename, 'rb', buffering=2048000000) as fh:
            dict_obj = {}
            for line in fh:
                for index, element in enumerate(pattern.match(line).groups()):
                    dict_obj.update({index: element})
                yield {'DateTime': dict_obj[0], 'OutCome': dict_obj[2], 'Method': dict_obj[5].strip("', '"),
                       'UserName': dict_obj[8]}


def main():
    """
        Parse log file and output results to CSV file

    Args:
        None

    Returns:
        CSV file
    """
    root_path = '/Users/alienone/Programming/python/'
    path_regex = '*.log*'
    parser_regex = r'(\d+\-\d+\-\d+\s+\d+\:\d+\:\d+\+\d+)' \
        r'\s+(\[\-\])\s+(AUTH SUCCESS)+\s+\W+(\w+\W+\d+)\W+(\w+)' \
        r'\W+(\w+\s+\w+\s+\w+\s+\w+\s+\w+\W+\w+\W+\w+\W+\w+\W+\w+\W+)' \
        r'(\w+)\W+(\w+)\W+(\w+)\W+(\w+)\W+(\w+)\W+(\w+)\W+(\w+)' \
        r'\W+(\w+)\W+(\w+)\W+(\w+)\W+(\w+)\W+(\d+)\W+(\w+\W+)'
    products = [product for product in parse_file(root_path, path_regex, parser_regex)]
    headers = ['DateTime', 'OutCome', 'Method', 'UserName']
    with open('test.csv', 'w', buffering=2048000000) as fh:
        w = csv.DictWriter(fh, headers)
        w.writeheader()
        w.writerows(products)
    
    print ("Completed")


if __name__ == '__main__':
    main()
