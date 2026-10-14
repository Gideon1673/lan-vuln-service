"""
Bước này Lấy mức độ nghiêm trọng và tạo Finding chứa thông tin thiết bị, phần mềm, phiên bản, CPE, mã CVE, điểm CVSS,
trạng thái đánh giá và bằng chứng như HTTP Banner cùng đường dẫn tham chiếu NVD.


"""
import re
from itertools import zip_longest

from packaging.version import Version, InvalidVersion


def compare_versions(a, b):
    pattern = r"(\d+(?:\.\d+)*)(?:p(\d+))?"

    ma = re.fullmatch(pattern, a, re.IGNORECASE)
    mb = re.fullmatch(pattern, b, re.IGNORECASE)

    if ma and mb:
        va = [int(x) for x in ma.group(1).split(".")]
        vb = [int(x) for x in mb.group(1).split(".")]

        for x, y in zip_longest(va, vb, fillvalue=0):
            if x != y:
                return (x > y) - (x < y)

        pa = int(ma.group(2) or 0)
        pb = int(mb.group(2) or 0)

        return (pa > pb) - (pa < pb)

    try:
        va = Version(a)
        vb = Version(b)
        return (va > vb) - (va < vb)
    except InvalidVersion:
        return None


def check_criterion(criterion, cpe_name):
    """
    Return:
        True  = tiêu chí phù hợp
        False = tiêu chí không phù hợp
        None  = chưa đủ thông tin
    """
    expected = criterion["criteria"].split(":")
    actual = cpe_name.split(":")

    if len(expected) != 13 or len(actual) != 13:
        return None

    # Part, vendor, product
    for index in (2, 3, 4):
        if expected[index] not in ("*", actual[index]):
            return False

    # Exact version
    if expected[5] not in ("*", actual[5]):
        return False

    version = actual[5]

    bounds = (
        ("versionStartIncluding", -1, True),
        ("versionStartExcluding", -1, False),
        ("versionEndIncluding", 1, True),
        ("versionEndExcluding", 1, False)
    )

    for field, invalid_side, inclusive in bounds:
        bound = criterion.get(field)

        if not bound:
            continue

        result = compare_versions(version, bound)

        if result is None:
            return None

        if result == invalid_side:
            return False

        if result == 0 and not inclusive:
            return False

    # Các thành phần CPE khác chưa biết chính xác
    # thì không được khẳng định match hoàn toàn.
    for index in range(6, 13):
        if expected[index] not in ("*", actual[index]):
            return None

    return True


def match_cve(cve, cpe_name):
    """
    V1 kiểm tra các vulnerable cpeMatch.
    Các cấu hình AND / negate chưa được xác minh
    hoàn toàn sẽ được đánh dấu NEEDS_REVIEW.
    """
    results = []

    for config in cve.get("configurations", []):
        config_complex = (config.get("operator") == "AND" or config.get("negate", False))

        for node in config.get("nodes", []):
            criteria = node.get("cpeMatch", [])

            node_complex = (
                    config_complex
                    or node.get("operator") == "AND"
                    or node.get("negate", False)
                    or bool(node.get("nodes"))
                    or any(not item.get("vulnerable", False) for item in criteria)
            )

            for item in criteria:
                if not item.get("vulnerable", False):
                    continue

                result = check_criterion(item, cpe_name)

                if result is False:
                    continue

                status = ("NEEDS_REVIEW" if result is None or node_complex else "POTENTIAL")
                results.append(status)

    if not results:
        return None

    if "POTENTIAL" in results:
        return "POTENTIAL"

    return "NEEDS_REVIEW"


def get_cvss(cve):
    metrics = cve.get("metrics", {})

    for field in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        records = metrics.get(field, [])
        if not records:
            continue

        metric = next(
            (
                record for record in records
                if record.get("type") == "Primary"
            ),
            records[0]
        )

        data = metric.get("cvssData", {})

        return (
            data.get("baseScore"),
            data.get("baseSeverity", metric.get("baseSeverity", "UNKNOWN"))
        )

    return None, "UNKNOWN"
