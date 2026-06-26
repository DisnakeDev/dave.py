import gc
import weakref

import dave


class CyclicSessionContainer:
    def __init__(self) -> None:
        # set mls_failure_callback
        self.session = dave.Session(self.callback)

    def callback(self, func: str, reason: str) -> None:
        pass


def test_session_leak() -> None:
    # only keep a weak reference to container
    ref = weakref.ref(CyclicSessionContainer())
    # this should collect the container and session
    gc.collect()
    # if the gc couldn't clear the cyclic reference, the object will still be alive at this point
    assert ref() is None
