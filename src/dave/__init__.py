from __future__ import annotations

from dave._dave_impl import *  # pyright: ignore[reportMissingModuleSource]  # noqa: F403


# https://daveprotocol.com/#displayable-codes
def generate_displayable_code(
    data: bytes | bytearray | memoryview,
    target_length: int,
    group_size: int,
) -> str:
    # "Ensure that the input data length is equal to or greater than the desired code length"
    if len(data) < target_length:
        raise ValueError("input data length smaller than desired code length")
    # "Ensure that the desired code length is a multiple of the group size"
    if target_length % group_size != 0:
        raise ValueError("desired code length must be multiple of group size")
    # "Ensure that the group size is smaller than 8"
    if group_size >= 8:
        raise ValueError("group size must be smaller than 8")

    group_modulo = 10**group_size

    groups: list[str] = []

    # "For the number of groups (desired_code_length / group_size)"
    for offset in range(0, target_length, group_size):
        # "Create an unsigned integer of group_size_bytes with the next group_size_bytes of the
        # input data, filled from most significant byte to least significant byte"
        value = int.from_bytes(data[offset : offset + group_size], "big", signed=False)
        # "Modulo the generated unsigned integer by 10 ^ group_size"
        value %= group_modulo
        # "pad the result with leading zeros to create a string of length group size"
        groups.append(str(value).rjust(group_size, "0"))

    return "".join(groups)
