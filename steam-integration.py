#!/bin/python
from subprocess import *
from threading import *

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
from gi.repository import GObject
from gi.repository import GLib

import sys,signal


class ProcessProcesser(GObject.GObject, Thread):
    def __init__(self, proc, win):
        # self.__gobject_init__()
        Thread.__init__(self)
        self.proc = proc
        self.win = win

    def emit(self, line):
        try:
            self.win.emit(line)
        except Exception:
            # print('huhhhh')
            pass

    def run(self):
        t = current_thread()
        while getattr(t, "alive", True) and self.proc.poll() == None:
            # print('a')
            line = self.proc.stdout.readline().rstrip('\n')
            if(line == ""): continue
            print('[Thread] from child: ', line)
            if line == "logged in: false":
                call(["dunstify", "-a", "Steam", "-u", "normal", "steam-integration failed to log in"])
                self.proc.kill()
            elif line == "logged in: true":
                call(["dunstify", "-a", "Steam", "-u", "normal", "steam-integration loaded successfully!"])
                self.win.hide()
            GLib.idle_add(lambda: self.emit(line))
        print('Child process handler thread closing...')


class SteamGuardDialog(Gtk.Dialog):
    def __init__(self, parent):

        # self.guardGrid = Gtk.Grid()
        # self.guardInput = Gtk.Entry()
        # self.guardButton = Gtk.Button(label="Login")
        # self.guardButton.connect("clicked", self.doSteamGuard)
        # self.guardGrid.attach(self.guardInput, 0, 0, 1, 1)
        # self.guardGrid.attach(self.guardButton, 0, 1, 1, 1)

        Gtk.Dialog.__init__(self, "Steam Guard", parent, 0)

        self.set_default_size(150, 100)
        self.set_resizable(False)

        self.parent = parent

        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        self.add_button("Submit", Gtk.ResponseType.OK)
        self.set_response_sensitive(Gtk.ResponseType.OK, False)

        label = Gtk.Label(label="Please enter your Steam Guard code:")
        field = Gtk.Entry()
        field.set_max_length(5)
        field.connect('changed', self.editCode)
        field.connect('activate', self.submitCode)

        box = self.get_content_area()
        box.add(label)
        box.add(field)
        self.show_all()

    def editCode(self, widget):
        self.parent.guardCode = widget.get_text()
        widget.set_text(self.parent.guardCode.upper())
        if(len(self.parent.guardCode) == 5):
            self.set_response_sensitive(Gtk.ResponseType.OK, True)
        else:
            self.set_response_sensitive(Gtk.ResponseType.OK, False)
    
    def submitCode(self, widget):
        if(len(self.parent.guardCode) == 5):
            self.response(Gtk.ResponseType.OK)

class LoginWindow(Gtk.Window, GObject.GObject):

    def __init__(self, proc):
        # self.__gobject_init__()
        Gtk.Window.__init__(self, title="steam-integration login")
        self.connect('InvalidPassword', lambda x: self.sendError('Invalid username/passsword combo!'))
        self.connect('SteamGuardReq', self.steamGuard)

        self.set_default_size(400, 270)
        self.set_resizable(False)

        self.guardCode = ""

        self.proc = proc
        self.dialog = None

        self.hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        self.makeLogin()

        self.add(self.hbox)

        self.login()

    def login(self):
        self.vbox.set_center_widget(self.grid)
        self.hbox.set_center_widget(self.vbox)

    def makeLogin(self):
        self.grid = Gtk.Grid()

        self.username = Gtk.Entry()
        self.password = Gtk.Entry()
        self.password.set_visibility(False)


        self.username.connect('activate', lambda _: self.password.grab_focus())
        self.password.connect('activate', self.doLogin)

        self.button = Gtk.Button(label="Login")
        self.button.connect("clicked", self.doLogin)

        self.error = Gtk.Label()
        self.error.set_line_wrap(True)
        self.error.set_justify(Gtk.Justification.CENTER)
        self.error.set_size_request(40, 40)
        self.error.set_single_line_mode(False)

        l = Gtk.Label(label="<span size='larger' weight='bold'>Steam Integration Login</span>")
        l.set_use_markup(True)
        l.set_margin_bottom(20)
        self.grid.attach(l, 0, 0, 1, 1)
        l = Gtk.Label(label="Username")
        l.set_justify(Gtk.Justification.LEFT)
        self.grid.attach(l, 0, 1, 1, 1)
        self.grid.attach(self.username, 0, 2, 1, 1)
        l = Gtk.Label(label="Password")
        l.set_justify(Gtk.Justification.LEFT)
        self.grid.attach(l, 0, 3, 1, 1)
        self.grid.attach(self.password, 0, 4, 1, 1)
        self.grid.attach(self.button, 0, 5, 1, 1)
        self.grid.attach(self.error, 0, 6, 1, 1)
    
    def steamGuard(self, x=None):
        if(self.dialog != None): return
        self.dialog = SteamGuardDialog(self)
        res = self.dialog.run()
        print(res)
        if res == Gtk.ResponseType.OK:
            self.doSteamGuard()
        elif res == Gtk.ResponseType.CANCEL:
            self.username.set_sensitive(True)
            self.password.set_sensitive(True)
            self.button.set_sensitive(True)

        self.dialog.destroy()
        self.dialog = None

    def doSteamGuard(self):
        print('{"type":2, "code":"%s"}' % self.guardCode, file=self.proc.stdin)

    def doLogin(self, widget):
        self.username.set_sensitive(False)
        self.password.set_sensitive(False)
        self.button.set_sensitive(False)
        print('{"type":0, "username":"%s", "password":"%s"}' % (self.username.get_text(), self.password.get_text()), file=self.proc.stdin)
    
    def sendError(self, txt):
        self.username.set_sensitive(True)
        self.password.set_sensitive(True)
        self.button.set_sensitive(True)
        self.error.set_text(txt)





def main():
    # GObject.threads_init()
    GObject.type_register(ProcessProcesser)
    GObject.signal_new("InvalidPassword", LoginWindow, GObject.SignalFlags.RUN_FIRST, GObject.TYPE_NONE, ())
    GObject.signal_new("SteamGuardReq", LoginWindow, GObject.SignalFlags.RUN_FIRST, GObject.TYPE_NONE, ())

    proc = Popen(['node', 'index.js'],
                stdin=PIPE, stdout=PIPE,
                bufsize=1, universal_newlines=True)

    

    win = LoginWindow(proc)

    # thread = Thread(target=processProc, args=[proc, win])
    # thread.start()
    processor = ProcessProcesser(proc,win)
    processor.start()

    win.connect("destroy", Gtk.main_quit)
    win.show_all()


    def shutdown():
        processor.alive=False
        proc.kill()
        sys.exit(0)

    def signal_handler(sig, frame):
        print()
        print('Received SIGINT, shutting down...')
        shutdown()
    
    signal.signal(signal.SIGINT, signal_handler)
    Gtk.main() # holds execution

    print('Checking if logged in...')
    print('{"type":1}', file=proc.stdin)

    proc.wait()
    shutdown()


    

if __name__ == "__main__":
    main()