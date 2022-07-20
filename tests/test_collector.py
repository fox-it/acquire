from unittest.mock import Mock

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem

from acquire.collector import Collector


def test_collector():
    target = Target("local")

    fs_1 = VirtualFilesystem()
    fs_1.map_file("$MFT", None)
    target.fs.mount("C:", fs_1)
    target.filesystems.add(fs_1)

    fs_2 = VirtualFilesystem()
    fs_2.map_file("$MFT", None)
    target.fs.mount("D:", fs_2)
    target.filesystems.add(fs_2)

    collector = Collector(target, Mock())
    collector.collect_file("$MFT", module_name="test")

    assert not collector.report.was_path_seen(fs_2.get("$MFT"))
