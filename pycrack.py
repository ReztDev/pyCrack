#!/usr/bin/python
import os
import sys
import time
import codecs
import hashlib
import platform
import argparse
try:
    from halo import Halo
except ImportError as error:
    print("[!] Please install modules 'halo'")
    sys.exit(0)

    
class Verbose:
    def __init__(self):
        self.process = Halo(spinner='dots')

    def mode_loading(self, text):
        self.process.start(text)

    def mode_info(self, text):
        self.process.succeed(text)

    def mode_failed(self, text):
        self.process.fail(text)


class IDHash(object):
    def __init__(self, passwords, wordlist):
        self.hash = passwords
        self.word = wordlist
        self.process = Verbose()

    def scanning_wordlist(self, wordlist):
        self.start_time = time.time()
        for word in range(len(wordlist)):
            self.process.mode_loading("\rScanning wordlist {f} of {s}".format(f=word, s=len(wordlist)))
            sys.stdout.flush()
        self.end_time = time.time()
        self.process.mode_info("Scanning completed!!")


class CrackingModule(IDHash):

    def run_crack(self):
        self.output = Verbose()
        self.os_platform = platform.system()
        print()
        self.output.mode_info("Starting crack password ...")
        self.output.mode_info("Running system on " + self.os_platform)

        if len(self.hash) == 32:
            self.MD5()
        elif len(self.hash) == 40:
            self.SHA1()
        elif len(self.hash) == 56:
            self.SHA224()
        elif len(self.hash) == 64:
            self.SHA256()
        elif len(self.hash) == 96:
            self.SHA384()
        elif len(self.hash) == 128:
            self.SHA512()
        else:
            self.process.mode_failed("Hash password not support!!")
            sys.exit()

    def MD5(self):
        try:
            with codecs.open(self.word, "r", encoding="utf-8", errors="ignore") as dictionary:
                words = dictionary.readlines()
            hashed = {}
            try:
                self.scanning_wordlist(words)
                for word in words:
                    hspwd = hashlib.md5()
                    hspwd.update(word[:-1].encode('utf-8'))
                    value = hspwd.hexdigest()
                    hashed[word[:-1]] = value
                for key, value in hashed.items():
                    if self.hash.lower() == value:
                        self.output.mode_info("Found passwords: " + key)
                        sys.exit(0)
                if not self.hash in value:
                    self.output.mode_failed("Not found passwords!!")
                    sys.exit(1)
            except KeyboardInterrupt:
                self.output.mode_failed("Interrupt user. Exiting ...!!")
        except IOError as IOE:
            self.output.mode_failed()

    def SHA1(self):
        try:
            with codecs.open(self.word, "r", encoding="utf-8", errors="ignore") as dictionary:
                words = dictionary.readlines()
            hashed = {}
            try:
                self.scanning_wordlist(words)
                for word in words:
                    hspwd = hashlib.sha1()
                    hspwd.update(word[:-1].encode('utf-8'))
                    value = hspwd.hexdigest()
                    hashed[word[:-1]] = value
                for key, value in hashed.items():
                    if self.hash.lower() == value:
                        self.output.mode_info("Found passwords: " + key)
                        sys.exit(0)
                if not self.hash in value:
                    self.output.mode_failed("Not found passwords!!")
                    sys.exit(1)
            except KeyboardInterrupt:
                self.output.mode_failed("Interrupt user. Exiting ...!!")
        except IOError as IOE:
            self.output.mode_failed()

    def SHA224(self):
        try:
            with codecs.open(self.word, "r", encoding="utf-8", errors="ignore") as dictionary:
                words = dictionary.readlines()
            hashed = {}
            try:
                self.scanning_wordlist(words)
                for word in words:
                    hspwd = hashlib.sha224()
                    hspwd.update(word[:-1].encode('utf-8'))
                    value = hspwd.hexdigest()
                    hashed[word[:-1]] = value
                for key, value in hashed.items():
                    if self.hash.lower() == value:
                        self.output.mode_info("Found passwords: " + key)
                        sys.exit(0)
                if not self.hash in value:
                    self.output.mode_failed("Not found passwords!!")
                    sys.exit(1)
            except KeyboardInterrupt:
                self.output.mode_failed("Interrupt user. Exiting...!!")
        except IOError as IOE:
            self.output.mode_failed()

    def SHA256(self):
        try:
            with codecs.open(self.word, "r", encoding="utf-8", errors="ignore") as dictionary:
                words = dictionary.readlines()
            hashed = {}
            try:
                self.scanning_wordlist(words)
                for word in words:
                    hspwd = hashlib.sha256()
                    hspwd.update(word[:-1].encode('utf-8'))
                    value = hspwd.hexdigest()
                    hashed[word[:-1]] = value
                for key, value in hashed.items():
                    if self.hash.lower() == value:
                        self.output.mode_info("Found passwords: " + key)
                        sys.exit(0)
                if not self.hash in value:
                    self.output.mode_failed("Not found passwords!!")
                    sys.exit(1)
            except KeyboardInterrupt:
                self.output.mode_failed("Interrupt user. Exiting ...!!")
        except IOError as IOE:
            self.output.mode_failed()

    def SHA384(self):
        try:
            with codecs.open(self.word, "r", encoding="utf-8", errors="ignore") as dictionary:
                words = dictionary.readlines()
            hashed = {}
            try:
                self.scanning_wordlist(words)
                for word in words:
                    hspwd = hashlib.sha384()
                    hspwd.update(word[:-1].encode('utf-8'))
                    value = hspwd.hexdigest()
                    hashed[word[:-1]] = value
                for key, value in hashed.items():
                    if self.hash.lower() == value:
                        self.output.mode_info("Found passwords: " + key)
                        sys.exit(0)
                if not self.hash in value:
                    self.output.mode_failed("Not found passwords!!")
                    sys.exit(1)
            except KeyboardInterrupt:
                self.output.mode_failed("Interrupt user. Exiting ...!!")
        except IOError as IOE:
            self.output.mode_failed()

    def SHA512(self):
        try:
            with codecs.open(self.word, "r", encoding="utf-8", errors="ignore") as dictionary:
                words = dictionary.readlines()
            hashed = {}
            try:
                self.scanning_wordlist(words)
                for word in words:
                    hspwd = hashlib.sha512()
                    hspwd.update(word[:-1].encode('utf-8'))
                    value = hspwd.hexdigest()
                    hashed[word[:-1]] = value
                for key, value in hashed.items():
                    if self.hash.lower() == value:
                        self.output.mode_info("Found passwords: " + key)
                        sys.exit(0)
                if not self.hash in value:
                    self.output.mode_failed("Not found passwords!!")
                    sys.exit(1)
            except KeyboardInterrupt:
                self.output.mode_failed("Interrupt user. Exiting ...!!")
        except IOError as IOE:
            self.output.mode_failed()


def main():
    parser = argparse.ArgumentParser(
                        prog=sys.argv[0],
                        description="Python Tools Single Brute Force Passwords Hash",
                        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80, width=100)
                        )
    parser.add_argument('-p', '--pass', dest='password', help='specify password hash (ex: 0603e7963203fc757932e0d3d715b21d)')
    parser.add_argument('-w', '--wordlist', dest='wordlist', help='specify file wordlist passwords')
    parser.add_argument('-v', '--version', dest='version', action='store_true', help='show version tools')
    crack = parser.parse_args()
    if len(sys.argv) <= 1:
        parser.print_help()
    elif crack.version:
        print("Version 1.0.0")
        print("Support hash: MD5, SHA1, SHA224, SHA256, SHA384, SHA512")
        sys.exit()
    else:
        run = CrackingModule(crack.password, crack.wordlist)
        run.run_crack()


if __name__ == "__main__":
    main()
        
