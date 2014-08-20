""" A python script similar to the c_rehash script from the openssl package """

###                                                                         ###
### Usage:                                                                  ###
### python c_rehash.py --clean --ca-path /etc/ssl/certs                     ###
### python c_rehash.py --ca-path /etc/ssl/certs --openssl-path /bin/openssl ###
###                                                                         ###

import argparse
import glob
import io
import logging
import mmap
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
from subprocess import CalledProcessError


def symlink(src, dst):
    """ platform specific symlink """

    try:
        if platform.system() == "Windows":
            logging.debug("symlink: windows, using cp")
            shutil.copy2(src, dst)
        else:
            logging.debug("symlink: not windows, symlinking")
            os.symlink(src, dst)
    except OSError:
        logging.exception("Error creating the hash file: " + dst)


def runcmd(commandline):
    """ run a command and return its output """

    try:
        lexout = shlex.split(commandline)
        logging.debug("runcmd: commandline: " + commandline)
        logging.debug("runcmd: lexout: " + str(lexout))
        processoutput = subprocess.check_output(lexout)
        return processoutput
    except CalledProcessError:
        logging.exception("Command Error")


def isfilex(path):
    """ is file exectuable """

    logging.debug("isfilex: path: " + path)
    return os.path.isfile(path) and os.access(path, os.X_OK)


def isvalidcertificate(fname):
    """ does fname contain the certificate header and footer """

    logging.debug("isvalidcertificate: fname: " + fname)
    infile = io.open(fname, "r+")
    buf = mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)

    if not (buf.find('-----BEGIN CERTIFICATE-----') == -1 or
            buf.find('-----END CERTIFICATE-----') == -1):
        logging.debug("isvalidcertificate: valid certificate")
        return True

    logging.debug("isvalidcertificate: invalid certificate")
    return False


def isvalidcrl(fname):
    """ does fname contain the crl header and footer """

    logging.debug("isvalidcrl: fname: " + fname)
    infile = io.open(fname, "r+")
    buf = mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)

    if not (buf.find('-----BEGIN X509 CRL-----') == -1 or
            buf.find('-----END X509 CRL-----') == -1):
        logging.debug("isvalidcrl: valid crl")
        return True

    logging.debug("isvalidcrl: invalid crl")
    return False


def rehash(inargs, root, fname, path, iscertificate):
    """ handle collisions and rehash the certificate or crl as required """

    if iscertificate:
        cparam = 'x509'
    else:
        cparam = 'crl'

    chash = runcmd(inargs.opath +
                   ' %s -hash -noout -in %s' %(cparam, path))
    chash = str(chash).strip()
    logging.debug("rehash: chash: " + chash)

    maxsuffix = -1
    duplicatefile = False
    hashfiles = glob.glob(os.path.join(path, chash + '*'))
    if hashfiles:
        #process for hash collisions here
        hashfiles.sort()

        logging.debug("rehash: collisions: " + str(hashfiles))
        cfprint = runcmd(inargs.opath +
                         ' %s -fingerprint -noout -in %s' %(cparam, path))
        cfprint = str(cfprint).strip()
        logging.debug("rehash: cfprint: " + cfprint)

        for exfile in hashfiles:
            efprint = runcmd(inargs.opath +
                             ' %s -fingerprint -noout -in %s' %(cparam, path))
            efprint = str(efprint).strip()
            logging.debug("rehash: efprint: " + efprint)

            if cfprint == efprint:
                logging.debug("rehash: duplicate certificate")
                duplicatefile = True
                break
            else:
                maxsuffix = int(os.path.splitext(exfile)[1][1:])

    maxsuffix = maxsuffix + 1

    if not iscertificate:
        #the symlinks to CRL files are of the format <hash>.rX
        maxsuffix = 'r' + str(maxsuffix)

    if not duplicatefile:
        # ln -s <path> <hash>.0
        src = fname
        dst = os.path.join(root, chash) + '.' + str(maxsuffix)
        logging.debug("creating symlink src: " + src + " dst: " + dst)
        symlink(src, dst)


def walkdirectory(inargs):
    """ walk through the cpath and perform the required actions """

    hexpattern = re.compile(r'^[\da-f]+\.r{0,1}\d+$')

    for root, _, files in os.walk(inargs.cpath):
        for fname in files:
            path = os.path.join(root, fname)
            logging.info("processing " + path + "...")

            hexfname = re.search(hexpattern, fname)

            if inargs.clean == True:
               # if cleanup is specified, unlink the <hash>.[r]X files
                if (os.path.islink(path) or hexfname):
                    logging.debug("walkdirectory: unlinking " + path)
                    os.unlink(path)
                continue
            elif (isvalidcertificate(path) and not hexfname):
                rehash(inargs, root, fname, path, True)
            elif (isvalidcrl(path) and not hexfname):
                rehash(inargs, root, fname, path, False)


def main():
    """ the main method """

    parser = argparse.ArgumentParser(description="""Run through the root
                                                    certificates and CRLs in the
                                                    CApath and create the
                                                    corresponding <hash>.[r]X
                                                    symlinks.""")

    parser.add_argument('--openssl-path',
                        dest='opath',
                        required=True,
                        help='path to the openssl binary to use',
                        metavar='/path/to/openssl')

    parser.add_argument('--ca-path',
                        dest='cpath',
                        required=True,
                        help='path to the root certificates and CRLs',
                        metavar='/path/to/rootcertificates')

    parser.add_argument("--clean",
                        dest="clean",
                        action='store_true',
                        help="when specified unlinks existing symlinks")

    args = parser.parse_args()

    #
    # validate the input
    #

    logging.debug("opath: " + args.opath)
    logging.debug("cpath: " + args.cpath)
    logging.debug("clean: " + str(args.clean))

    if not isfilex(args.opath):
        errmsg = "Input Error: %s is not a file or executable" %args.cpath
        logging.exception(errmsg)
        sys.exit(1)

    if not os.path.exists(args.cpath) and not os.path.isdir(args.cpath):
        errmsg = "Input Error: %s does not exist or not a directory" %args.cpath
        logging.exception(errmsg)
        sys.exit(1)

    versionstr = runcmd(args.opath + " version")
    logging.info("using " + versionstr)

    walkdirectory(args)

if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)

        main()
    except Exception, ex:
        logging.exception("Unhandled Exception")
        sys.exit(1)

