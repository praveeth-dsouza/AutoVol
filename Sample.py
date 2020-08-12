import datetime
from lib.util1 import calc_md5, calc_sha256, calc_sha1



class SampleDump:
    def __init__(self,binary_path):
        self.id = None
        self.parent_sample_id = None
        self.md5 = None
        self.sha256 = None
        self.imphash = None
        self.ephash = None
        self.process_name = None
        self.source = None
        self.binary_path = binary_path
        self.timestamp = datetime.datetime.now()
        return

    def calculate_hashes(self):
        self.md5 = calc_md5(self.binary_path)
        self.sha256 = calc_sha256(self.binary_path)
        self.sha1 = calc_sha1(self.binary_path)

    def report(self):
        pass
