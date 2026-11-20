import importlib.util
from pathlib import Path
import platform
import threading
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "encap.py"
SPEC = importlib.util.spec_from_file_location("encap_sleep_test", SOURCE)
ENCAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENCAP)


@unittest.skipUnless(platform.system() == "Darwin", "macOS power notifications")
class SleepWatcherTest(unittest.TestCase):
    def setUp(self):
        self.watch = ENCAP.SleepWatcher().start()
        self.addCleanup(self.watch.stop)

    def test_registers_for_system_power(self):
        self.assertTrue(self.watch.root)
        self.assertTrue(self.watch.loop)
        self.assertFalse(self.watch.sleeping.is_set())

    def test_sleep_is_held_until_the_tunnel_is_closed(self):
        notice = threading.Thread(target=self.watch._callback, args=(None, 0, ENCAP.SleepWatcher.WILL_SLEEP, None))
        notice.start()
        self.assertTrue(self.watch.sleeping.wait(1))
        notice.join(0.3)
        self.assertTrue(notice.is_alive(), "sleep must wait for the tunnel to close")
        self.watch.release()
        notice.join(1)
        self.assertFalse(notice.is_alive())

    def test_sleep_check_is_answered_at_once(self):
        notice = threading.Thread(target=self.watch._callback, args=(None, 0, ENCAP.SleepWatcher.CAN_SLEEP, None))
        notice.start()
        notice.join(1)
        self.assertFalse(notice.is_alive())
        self.assertFalse(self.watch.sleeping.is_set())


if __name__ == "__main__":
    unittest.main()
