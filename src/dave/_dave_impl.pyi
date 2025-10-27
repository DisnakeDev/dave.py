from collections.abc import Callable, Sequence, Set
import enum


k_init_transition_id: int = 0

k_disabled_version: int = 0

class RejectType(enum.IntEnum):
    failed = 0

    ignored = 1

class MediaType(enum.IntEnum):
    audio = 0

    video = 1

class Codec(enum.IntEnum):
    unknown = 0

    opus = 1

    vp8 = 2

    vp9 = 3

    h264 = 4

    h265 = 5

    av1 = 6

def get_max_supported_protocol_version() -> int: ...

class SignaturePrivateKey:
    pass

class MlsKeyRatchet:
    pass

class Session:
    def __init__(self, context: str, auth_session_id: str, mls_failure_callback: Callable[[str, str], None]) -> None: ...

    def init(self, version: int, group_id: int, self_user_id: str, transient_key: SignaturePrivateKey | None) -> None: ...

    def reset(self) -> None: ...

    def set_protocol_version(self, version: int) -> None: ...

    def get_protocol_version(self) -> int: ...

    def get_last_epoch_authenticator(self) -> list[int]: ...

    def set_external_sender(self, external_sender_package: bytes) -> None: ...

    def process_proposals(self, proposals: bytes, recognized_user_ids: Set[str]) -> bytes | None: ...

    def process_commit(self, commit: bytes) -> RejectType | dict[int, list[int]]: ...

    def process_welcome(self, welcome: bytes, recognized_user_ids: Set[str]) -> dict[int, list[int]] | None: ...

    def get_marshalled_key_package(self) -> bytes: ...

    def get_key_ratchet(self, user_id: str) -> MlsKeyRatchet | None: ...

    def get_pairwise_fingerprint(self, version: int, user_id: str, callback: Callable[[Sequence[int]], None]) -> None: ...

class Encryptor:
    def __init__(self) -> None: ...

    def set_key_ratchet(self, key_ratchet: MlsKeyRatchet | None) -> None: ...

    def set_passthrough_mode(self, passthrough_mode: bool) -> None: ...

    def has_key_ratchet(self) -> bool: ...

    def is_passthrough_mode(self) -> bool: ...

    def assign_ssrc_to_codec(self, ssrc: int, codec_type: Codec) -> None: ...

    def codec_for_ssrc(self, ssrc: int) -> Codec: ...

    def encrypt(self, media_type: MediaType, ssrc: int, frame: bytes) -> bytes | None: ...

    def get_max_ciphertext_byte_size(self, media_type: MediaType, frame_size: int) -> int: ...

    def set_protocol_version_changed_callback(self, callback: Callable[[], None]) -> None: ...

    def get_protocol_version(self) -> int: ...
