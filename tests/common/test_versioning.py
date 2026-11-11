from swinventory.common.versioning import compare_versions, latest_version


def test_numeric_tokens_compare_as_numbers_not_strings():
    assert compare_versions("5.15.0-100-generic", "5.15.0-91-generic") == 1
    assert compare_versions("5.15.0-91-generic", "5.15.0-100-generic") == -1


def test_equal_versions():
    assert compare_versions("5.15.0-91-generic", "5.15.0-91-generic") == 0


def test_rpm_style_release():
    assert compare_versions("5.14.0-362.8.1.el9_3.x86_64", "5.14.0-427.13.1.el9_4.x86_64") == -1


def test_longer_version_with_same_prefix_is_newer():
    assert compare_versions("10.0.22631.3085", "10.0.22631") == 1


def test_windows_build_numbers():
    assert compare_versions("10.0.22631.3085", "10.0.22631.3155") == -1


def test_latest_version():
    assert latest_version(["5.15.0-91-generic", "5.15.0-100-generic", "5.4.0-1-generic"]) == "5.15.0-100-generic"
    assert latest_version([]) is None
