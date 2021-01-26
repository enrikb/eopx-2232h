from __future__ import print_function

import os
import pkgutil
import signal
import sys
import threading

import frida
from frida_tools.application import Reactor

class EOPX(object):

    def __init__(self, argv):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda reactor: self._stop_requested.wait())

        self._device = frida.get_local_device()
        self._sessions = set()

        self._device.on("child-added", lambda child: self._reactor.schedule(lambda: self._on_child_added(child)))
        self._device.on("child-removed", lambda child: self._reactor.schedule(lambda: self._on_child_removed(child)))
        self._device.on("output", lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data)))
        self._argv = argv
        script = pkgutil.get_data(__package__, 'eopx-2232h.js')
        self._script = script.decode('UTF-8', 'ignore')

    def run(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        pid = self._device.spawn(self._argv, stdio='pipe')
        self._instrument(pid, True)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument(self, pid, load):
        print("✔ attach(pid={})".format(pid), file=sys.stderr)
        session = self._device.attach(pid)
        session.on("detached", lambda reason: self._reactor.schedule(lambda: self._on_detached(pid, session, reason)))
        print("✔ enable_child_gating()", file=sys.stderr)
        session.enable_child_gating()
        print("✔ create_script()", file=sys.stderr)
        script = session.create_script(self._script)
        script.on("message", lambda message, data: self._reactor.schedule(lambda: self._on_message(pid, message)))
        print("✔ load()", file=sys.stderr)
        if load:
            script.load()
        print("✔ resume(pid={})".format(pid), file=sys.stderr)
        self._device.resume(pid)
        self._sessions.add(session)

    def _on_child_added(self, child):
        print("⚡ child_added: {}".format(child), file=sys.stderr)
        self._instrument(child.pid, True)

    def _on_child_removed(self, child):
        print("⚡ child_removed: {}".format(child), file=sys.stderr)
        pass

    def _on_output(self, pid, fd, data):
        ###print("⚡ output: pid={}, fd={}, data={}".format(pid, fd, repr(data)))
        if fd == 1: sys.stdout.buffer.write(data)
        if fd == 2: sys.stderr.buffer.write(data)

    def _on_detached(self, pid, session, reason):
        print("⚡ detached: pid={}, reason='{}'".format(pid, reason), file=sys.stderr)
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

    def _on_message(self, pid, message):
        print("⚡ message: pid={}".format(pid), file=sys.stderr)
        print("⚡ message: ", repr(message), file=sys.stderr)
