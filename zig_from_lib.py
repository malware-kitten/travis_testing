import sys
import r2pipe
import multiprocessing
import argparse
import subprocess
import tempfile
import os
import simplejson as json
import shutil
import logging
from pprint import pprint, pformat
from pathlib import Path

def normalize_name(fname):
    #given a filename, return back the appropiate zig name
    #a normal path should include the following
    #C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\lib\amd64\foo.lib
    file_path = Path(fname)
    arch = None
    basename = file_path.stem
    for elem in file_path.parts:
        if elem == "amd64" or elem == "arm":
            arch = elem
        if "Visual Studio" in elem:
            vs_version = elem.split(' ')[-1]
    if arch:
        filename = "VisualStudio%s_%s_%s.zig" % (vs_version, arch, basename)
    else:
        filename = "VisualStudio%s_x86_%s.zig" % (vs_version, basename)
    return filename

def mkdir_wrapper(path, is_dir=True):
    if not is_dir:
        path = os.path.split(path)[0]
    if path != '':
        import errno
        try:
            os.makedirs(path)
            return True
        except OSError as e:
            if e.errno == errno.EEXIST and os.path.isdir(path):
                return False
            else:
                raise
        except Exception as e:
            raise
    return False
     
def recursive_all_files(directory, ext_filter=None):
    all_files = []
    dir_content = []
    ret = []
    if os.path.isfile(directory):
        dir_content = [directory]
    else:
        if '*' in directory:
            dir_content = glob.glob(directory)
        else:
            try:
                dir_content = os.listdir(directory)
            except Exception as e:
                return []
    for f in dir_content:
        if os.path.isdir(directory):
            rel_path = os.path.join(directory,f)
        else:
            rel_path = f
        if os.path.isfile(rel_path):
            all_files.append(rel_path)
        elif f == '.' or f == '..':
            pass
        else:
            all_files += recursive_all_files(rel_path,ext_filter)

    for f in all_files:
        if (ext_filter is None or os.path.splitext(f)[1] == '.%s' % ext_filter):
            ret.append(f)
    return ret

def generate_zigs_json(f):
    r2p = r2pipe.open(f)
    r2p.cmd('aaa; zg')
    zigs = r2p.cmdj('zj')
    r2p.quit()
    return zigs

def dedup(zignatures):
    observed = {}
    uniq_results = []
    for zig in zignatures:
        if zig['bytes'] in observed:
            logger.debug("Removing %s" % zig)
        else:
            observed[zig['bytes']] = 1
            uniq_results.append(zig)
    return uniq_results

def worker(queue, shared_results, lock):
    while not queue.empty():
        obj = queue.get(True)
        logger.debug(" - %s" % obj)
        json_items = generate_zigs_json(obj)
        with lock:
            for zigs in json_items:
                shared_results.append(zigs)

def process_single_file(fname, oname, num_threads):
    with open(fname,'rb') as fp:
        contents = fp.read(7)
    if contents == b'!<arch>':
        target_path = tempfile.mkdtemp(dir=".")
        command = ['7z', 'x', '-o'+target_path, fname]
        logger.debug("Building tmp location at %s" % target_path)
        logger.debug(command)
        output = subprocess.check_output(command)
        logger.debug(output)
        queue = multiprocessing.Queue()
        lock = multiprocessing.Lock()
        manager = multiprocessing.Manager()
        shared_results = manager.list()
        for f in recursive_all_files(target_path, 'obj'):
            queue.put(f)
        logger.info("%s : %s" % (fname, queue.qsize()))
        pool = multiprocessing.Pool(num_threads, worker, (queue, shared_results, lock))
        pool.close()
        pool.join()
    else:
        logger.error("File magic does not match, check to make sure this is a .lib file")
        return
    #cleanup
    shutil.rmtree(target_path)
    uniq_results = dedup(shared_results)
    if len(uniq_results) > 0:
        with open(oname, 'w') as fp:
            fp.write(pformat(uniq_results))

def process_directory(target_path, target_directory, num_threads):
    processed = []
    mkdir_wrapper(target_directory)
    for fname in recursive_all_files(target_path, 'lib'):
        output_name = normalize_name(fname)
        oname = str(Path(target_directory) / output_name)
        if oname in processed:
            continue
        else:
            process_single_file(fname, oname, num_threads)

def configure_logger(log_level):
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3) #clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level], 
            format='%(asctime)s - %(name)s - %(levelname)-8s %(message)s')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate R2 Zignatures from .lib files')
    group_toplevel = parser.add_mutually_exclusive_group(required=True)
    group_toplevel.add_argument("-f", "--file", help=".lib file to use")
    group_toplevel.add_argument("-d", "--dir", help="directory to scan for libs")
    parser.add_argument("-o", "--output",required=True,help="output filename or directory")
    parser.add_argument("-s", "--sdb", action='store_true', help="store as sdb files")
    parser.add_argument("-t", "--threads", default=8, type=int, help="number of threads, default 8")
    parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    args = parser.parse_args()
    
    configure_logger(args.verbose)
    logger = logging.getLogger("MS_Zig_Parser")

    if args.file:
        process_single_file(args.file, args.output, args.threads)
    if args.dir:
        process_directory(args.dir, args.output, args.threads)
