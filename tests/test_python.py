import pytest

import dave

# These tests are only for the parts implemented in Python, and none of the native C++ stuff.


# see https://github.com/discord/libdave/blob/main/js/__tests__/DisplayableCode-test.ts
class TestGenerateDisplayableCode:
    def test_short(self) -> None:
        data = b"\xaa\xbb\xcc\xdd\xee"
        assert dave.generate_displayable_code(data, 5, 5) == "05870"

    def test_long(self) -> None:
        data = bytes.fromhex("aabbccddeebbccddeeffccddeeffaaddeeffaabbeeffaabbccffaabbccdd")
        assert dave.generate_displayable_code(data, 30, 5) == "058708105556138052119572494877"

    def test_invalid(self) -> None:
        data = b"\xaa\xbb\xcc\xdd"
        with pytest.raises(ValueError, match=r"smaller than desired code length"):
            dave.generate_displayable_code(data, 5, 5)

        with pytest.raises(ValueError, match=r"must be multiple of group size"):
            dave.generate_displayable_code(data, 4, 3)

        data = bytes(1024)
        with pytest.raises(ValueError, match=r"group size must be smaller than 8"):
            dave.generate_displayable_code(data, 1024, 16)
