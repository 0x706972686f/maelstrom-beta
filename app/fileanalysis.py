#!/usr/bin/python3

"""
Script Description
"""

import pefile
import sys
import hashlib
import pathlib
import os
import base64
import string
import zipfile
import pyminizip
import re
import exiftool
import math
import clamd
import yara
import ntpath
import ssdeep

MINIMUMSTRINGLENGTH=8
ZIPPASSWORD='infected'
VIRUSTOTALAPI=''
DEFAULTYARARULE='yararules/index.yar'

'''
Object: fileAnalysis

Properties:
        filepath - the path of the file submitted, including the filename (e.g: /path/to/file.extension)
        filename - just the filename
        filesize - the size of the file in bytes
        fileextension - the displayed file extension, this is not based on the magic file byte
        sha256hash - the sha256 hash of the file (not the filename)
        md5hash - the MD5 hash of the file (not the filename)

Functions:
        convertbytes - converts bytes to human readable sizes based on SI units (B, kB, MB, GB, TB)
        hexdump - creates a hexdump of a contents of a file, similar to running the xxd command in linux
        base64decode - decodes an input string from base64
        identifystrings - reads a file, identifies strings and then returns the results
        create_zip - creates a password protected zip file containing the sample

        get_filesizehuman - returns the human readable filesize
        get_strings - returns the strings identified in a file
        get_filemetadata - uses the exiftool library to identify metadata of a file
        get_clamavresult - passes a file into ClamAV for malware detection, returns JSON result
        get_yararule - compiles all of the yararules from within the `yararules` directory, and then reports any matches
        get_fileentropy - calculates the shannon entropy on a file, this can be used to identifying compressed/packed/encrypted files


'''
class fileAnalysis(object):
        def __init__(self, filepath):
                self.filepath = filepath
                self.filename = self.set_filename()
                self.filesize = self.set_filesize()
                self.fileextension = self.set_fileextension()
                self.sha256hash = self.set_sha256hash()
                self.md5hash = self.set_md5hash()
                self.ssdeephash = self.set_ssdeephash()

        """
        Set Functions
        """
        def set_filename(self):
                head, tail = ntpath.split(self.filepath)
                return tail or ntpath.basename(head)

        def set_fileextension(self):
                return self.filepath.split(".")[-1]

        def set_filesize(self):
                fileinfo = os.stat(self.filepath)
                return fileinfo.st_size

        def set_sha256hash(self):
                return hashlib.sha256(open(self.filepath,'rb').read()).hexdigest()

        def set_md5hash(self):
                return hashlib.md5(open(self.filepath,'rb').read()).hexdigest()

        def set_ssdeephash(self):
                return ssdeep.hash_from_file(self.filepath)

        """
        Static Methods
        """
        @staticmethod
        def convertbytes(num):
                for x in ['B','kB','MB','GB','TB']:
                    if num < 1024.0:
                            return "%3.1f %s" % (num, x)
                    num /= 1024.0

        @staticmethod
        def hexdump(inputfile, length=16, sep='.'):
                result = []

                try:
                        xrange(0,1)
                except NameError:
                        xrange = range

                for i in xrange(0, len(inputfile), length):
                        subsrc = inputfile[i:i+length]
                        hexa = ''
                        ismiddle = False
                        for h in xrange(0,len(subsrc)):
                                if h == length/2:
                                        hexa += ' '
                                h = subsrc[h]
                                if not isinstance(h, int):
                                        h = ord(h)
                                h = hex(h).replace('0x', '')
                                if len(h) == 1:
                                        h = '0'+h;
                                hexa += h+' '
                        hexa = hexa.strip(' ')
                        text = ''
                        for c in subsrc:
                                if not isinstance(c, int):
                                        c = ord(c)
                                if 0x20 <= c < 0x7F:
                                        text += chr(c)
                                else:
                                        text += sep
                        result.append(('%08X:  %-'+str(length*(2+1)+1)+'s  %s') % (i, hexa, text))

                return '\n'.join(result)

        @staticmethod
        def base64decode(inputstring):
                return base64.b64decode(inputstring)

        @staticmethod
        def identifystrings(filename, min=MINIMUMSTRINGLENGTH):
                with open(filename, errors="ignore") as f:
                        result=""
                        for c in f.read():
                                if c in string.printable:
                                        result += c
                                        continue
                                if len(result) >= min:
                                        yield result
                                result = ""
                        if len(result) >= min:
                                yield result

        """
        Misc
        """
        def create_zip(self, zipname):
                pyminizip.compress(self.filepath, None, zipname, ZIPPASSWORD, 0)

        """
        Get Functions
        """
        def get_filesizehuman(self):
                return self.convertbytes(self.filesize)

       
        def get_strings(self):
                stringlist = list(self.identifystrings(self.filepath))
                return stringlist

        def get_filemetadata(self):
                with exiftool.ExifTool() as et:
                        metadata = et.get_metadata(self.filepath)
                return metadata

        def get_clamavresult(self):
                cd = clamd.ClamdUnixSocket()
                results = cd.scan(self.filepath)
                return results.get(self.filepath)

        def get_yararule(self):
                rules = yara.compile(DEFAULTYARARULE)
                matches = rules.match(self.filepath)
                return matches

        def get_fileentropy(self):
                H = {}
                with open(self.filepath, 'rb') as f:
                        bytearr = []
                        while True:
                                bytechunk = f.read(1)
                                if bytechunk:
                                        bytearr.append(ord(bytechunk))
                                else:
                                        break
                        f.close()
                        filesize = self.filesize

                        H['filesize'] = filesize

                        # calculate the frequency of each byte value in the file
                        freqlist = []
                        for b in range(256):
                                ctr = 0
                                for byte in bytearr:
                                        if byte == b:
                                                ctr += 1
                                # This will give the frequency of each byte-character
                                freqlist.append(float(ctr) / filesize)

                        # Shannon Entropy - between 0 and 8, higher 
                        entropy = 0.0
                        for freq in freqlist:
                                if freq > 0:
                                        # H(x) = H(X) + sum( log2(freq))        
                                        entropy = entropy + freq * math.log(freq, 2)
                        entropy = -entropy

                        H['entropy'] = entropy

                        # Minimum possible file size, assuming max theoretical compression
                        minfilesize = entropy * filesize
                        H['minfilesize'] = minfilesize

                        minfilesizebyte = (entropy * filesize) / 8
                        H['minfilesizebyte'] = minfilesizebyte

                        efficiency = (minfilesizebyte / filesize) * 100
                        H['efficiency'] = efficiency

                        """
                        https://www.kennethghartman.com/calculate-file-entropy/

                        You can use numpy and matplotlib to generate a graph to reflect it
                        This would make it easier to see

                        import numpy as np
                        import matplotlib.pyplot as plt

                        N = len(freqlist)
                        ind = np.arange(N) - the x locations for the groups
                        width = 1.00       - this is the width of the bars

                        fig = plt.figure(figsize=(11,5),dpi=100
                        ax = fig.add_subplot(111)
                        rects1 = ax.bar(ind, freqlist, width)
                        ax.set_autoscalex_on(False)
                        ax.set_xlim([0,255])

                        ax.set_ylabel('Frequency')
                        ax.set_xlabel('Byte')
                        ax.set_title('Frequency of Bytes (0-255) of File:' + filename)

                        plt.show()
                        """

                        return H        


'''
Object: exeAnalysis (inherits from fileAnalysis)

Functions:
        get_filehexdump - generates a hexdump of a file
        get_pesections - reports the size in bytes of the sections within a PE file
        get_pedumpall - dumps the entire contents of a PE binary
        get_peimports - reports the DLL files and the function calls that have been imported

'''

class exeAnalysis(fileAnalysis):
        def __init__(self,filepath):
                fileAnalysis.__init__(self,filepath)
                self.imphash = self.set_imphash()

        def set_imphash(self):
                pe = pefile.PE(self.filepath)
                return pe.imphash()


        def get_filehexdump(self):
                with open(self.filepath, 'rb') as f:
                        data = f.read()
                return self.hexdump(data)

        def get_pesections(self):
                pe = pefile.PE(self.filepath)
                return pe.sections

        def get_pedumpall(self):
                pe = pefile.PE(self.filepath)
                return pe.dump_info()

        def get_peimports(self):
                pe = pefile.PE(self.filepath)
                return pe.DIRECTORY_ENTRY_IMPORT



