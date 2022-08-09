Password compromise checker
======

Script that hashes password and calls haveibeenpwned API or checks hash against given wordlist to verify if it was compromised due to any database leaks.

Installation
------------

To install with pip, run:

    pip install pswrd-check

Quickstart Guide
----------------

You can run script either as a program or using switches.

When run as program:
    1. For web password check mode
    2. For wordlist check mode

Usage: pswrd-check.py [-h] [-w] [-p] <INPUT>
    Checks password against given wordlist or via haveibeenpwned api

    positional arguments:
        INPUT               -   either password or wordlist, mode dependend

    options:
        -h, --help          -   displays help info
        -w, --wordlist      -   wordlists mode, requires password list file to check typed password f.e -w <wordlist.txt> -p <password>
        -p, --password      -   default mode, checks password leaks via haveibeenpwned api

----------

If you'd like to contribute to password-compromise-checker, check out https://github.com/andsko92/pswrd-check
