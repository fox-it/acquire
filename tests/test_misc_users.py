from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem

from acquire.acquire import misc_unix_user_homes


def test_misc_unix_user_homes(mock_target: Target, mock_fs: VirtualFilesystem):
    mock_fs.makedirs("/root")
    expected_results = ["/root"]
    for user in ["Foo", "Bar"]:
        mock_fs.makedirs(f"/home/{user}")
        expected_results.append(f"/home/{user}")

    assert list(str(home) for home in misc_unix_user_homes(mock_target)) == expected_results
