import pefile
import hashlib



def calc_sha256(file_path):
    return hashlib.sha256(open(file_path, 'rb').read()).hexdigest()


def calc_sha1(file_path):
    return hashlib.sha1(open(file_path, 'rb').read()).hexdigest()


def calc_md5(file_path):
    return hashlib.md5(open(file_path, 'rb').read()).hexdigest()


def get_workdir_path(malware_sample):
    return os.path.dirname(os.path.realpath(malware_sample.file_path))

def calc_ephash(filename, bytes_to_read=64):
    retval = pe_read_x_bytes_from_ep(filename)
    logging.info("[*] Hash of " + str(bytes_to_read) + " Bytes at EP of: " + str(filename) + " : " + retval)
    return retval


def calc_imphash(filename):
    # There is a bug in pefile implenation of imphash in Py3.5. To be fixed
    """
    try:
        pe = pefile.PE(filename)
        return pe.get_imphash()
    except PEFormatError:
        return 'failed'
    """
    return 'failed'

