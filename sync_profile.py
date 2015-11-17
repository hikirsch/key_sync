#!/usr/bin/python

import os
import socket
import getpass
import sys
import paramiko


class SSHKey():
    key_comment = None
    key_type = None
    key_content = None

    def __init__(self, key):
        if len(key.strip()) == 0:
            raise KeyError("Blank Key")

        self.key_type, self.key_content, self.key_comment = key.strip().split(" ")

    def abridged(self):
        return "%s (%s)" % (self.key_comment, self.key_type)

    def __eq__(self, other):
        return self.key_comment == other.key_comment and self.key_type == other.key_type

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "%s %s %s" % (self.key_type, self.key_content, self.key_comment)

    def exact(self, other):
        return self.key_comment == other.key_comment and self.key_type == other.key_type and self.key_content == other.key_content


class SyncProfile():
    VERSION = "0.0.1"

    AUTHORIZED_KEYS_REMOTE_PATH = ".ssh/authorized_keys"
    TEMP_AUTHORIZED_KEYS_LOCAL_PATH = os.path.expanduser("~/.ssh/temp_authorized_keys")

    HOSTS_SYNCED_LOCAL_PATH = os.path.expanduser("~/.ssh/synced_hosts")
    OTHER_KEYS_LOCAL_PATH = os.path.expanduser("~/.ssh/synced_other_keys")

    PUBLIC_KEY_LOCAL_PATH = os.path.expanduser("~/.ssh/id_rsa.pub")

    PUBLIC_KEY = None
    OTHER_KEYS = None

    username = getpass.getuser()
    password = None

    local_hostname = socket.gethostname()

    sftp_client = None
    ssh_client = None

    def __init__(self):
        self.PUBLIC_KEY = self.read_key_file(self.PUBLIC_KEY_LOCAL_PATH)[0]
        self.OTHER_KEYS = self.read_file(self.OTHER_KEYS_LOCAL_PATH)

        self.banner()

        length = len(sys.argv)
        arg_min = 1
        arg_max = 2

        if len(sys.argv) < arg_min + 1 or len(sys.argv) > arg_max + 1:
            print "Must pass a valid command"
            self.show_help()

        else:
            command = sys.argv[1].lower()

            if length == 3:
                host = sys.argv[2].lower()

                if host == "all":

                    if command == "register":
                        self.register_all_hosts()

                    elif command == "unregister":
                        self.unregister_all_hosts()

                    else:
                        self.line("Invalid command '%s'" % command)
                        self.show_help()

                elif command == "unregister":
                    self.unregister_host(host)

                elif command == "register":
                    self.register_host(host)

                elif command == "exclude-key":
                    self.exclude_key(host)

                elif command == "include-key":
                    self.include_key(host)

                else:
                    self.line("Invalid command '%s'" % command)
                    self.show_help()

            elif command == "list":
                self.show_sync_hosts()

            elif command == "help":
                self.show_help()

            else:
                self.line("Invalid command '%s'" % command)
                self.show_help()

    def banner(self):
        self.log()
        self.log("SSH Key Sync - v%s" % self.VERSION, True)
        self.log()

        self.line("User: '%s'" % self.username)
        self.line("Local Hostname: '%s'" % self.local_hostname)
        self.line("Active Key: '%s'" % self.PUBLIC_KEY.abridged())
        self.log()
        self.line()

    def show_help(self):
        self.line("usage: %s CMD <HOST>" % "sync_profile")
        self.line()
        self.line("Valid Commands")
        self.line("  - help                      this documentation")
        self.line("  - list                      lists hosts synced")
        # self.line("  - clean <HOST>              remove all .ssh folders")
        self.line()
        self.line("  - register <HOST>           adds key is on host")
        self.line("  - unregister <HOST>         remove public key from host")
        self.line()
        self.line("  - exclude-key <KEY COMMENT> adds key is on host")
        self.line("  - include-key <KEY COMMENT> remove public key from host")
        self.line()
        self.line("NOTE: Host can be replaced by 'all' to reflect all hosts in other hosts file.")
        self.line()

    def exclude_key(self, key):
        self.OTHER_KEYS += [key]
        self.line("Adding key comment '%s' to exclude list." % key )
        self.save_file(self.OTHER_KEYS_LOCAL_PATH, self.OTHER_KEYS)
        self.line("Saved!")

    def include_key(self, key):
        if key in self.OTHER_KEYS:
            self.OTHER_KEYS.remove(key)
        # self.OTHER_KEYS += [key]
            self.line("Removing key comment '%s' from exclude list." % key)
            self.save_file(self.OTHER_KEYS_LOCAL_PATH, self.OTHER_KEYS)
            self.line("Saved!")
        else:
            self.line("Could not find '%s' in exclude list." % key)

    def show_sync_hosts(self):
        contents = self.read_file(self.HOSTS_SYNCED_LOCAL_PATH)

        self.line("Listing hosts:\n - %s" % "\n - ".join(contents))
        self.line()

        self.line("Listing ssh key comments to exclude:\n - %s" % "\n - ".join(self.OTHER_KEYS))

    def register_host(self, host_name):
        self.log()
        self.line("Registering '%s'" % host_name)
        self.log()

        self.login(host_name)

        self.get_key()

        new_keys = self.generate_new_authorized_keys()
        self.save_file(self.TEMP_AUTHORIZED_KEYS_LOCAL_PATH, new_keys)

        self.put_key()

        self.remove_local_host_key()

        self.disconnect()

        self.save_host(host_name)

        self.log()
        self.log()
        self.line()

    def unregister_host(self, host_name):
        self.line("Unregistering '%s'" % host_name)
        self.log()

        self.login(host_name)

        self.get_key()

        new_keys = self.generate_new_authorized_keys(False)
        self.save_file(self.TEMP_AUTHORIZED_KEYS_LOCAL_PATH, new_keys)

        self.put_key()

        self.remove_local_host_key()

        self.disconnect()

        # self.save_host(host_name, False)

        self.log()
        self.log()
        self.line()

    def generate_new_authorized_keys(self, include=True):
        host_keys = self.read_key_file(self.TEMP_AUTHORIZED_KEYS_LOCAL_PATH)

        new_host_keys = []
        removing_keys = []

        self.log("Generating authorized_keys file ... ", True)
        added_self = False

        for host_key in host_keys:
            if include and host_key == self.PUBLIC_KEY and host_key.key_content == self.PUBLIC_KEY.key_content:
                self.line(" found this host, keeping ")
                new_host_keys.append(self.PUBLIC_KEY)
                added_self = True

            elif include and host_key == self.PUBLIC_KEY and host_key.key_content != self.PUBLIC_KEY.key_content:
                self.line(" found this host, resetting ")
                new_host_keys.append(self.PUBLIC_KEY)
                added_self = True

            elif host_key.key_comment in self.OTHER_KEYS and host_key != self.PUBLIC_KEY:
                self.line(" keeping '%s'" % host_key.abridged())
                new_host_keys.append(host_key)

            else:
                if include and host_key == self.PUBLIC_KEY:
                    self.line(" removing this host")
                else:
                    self.line(" removing '%s'" % host_key.abridged())

                removing_keys.append(host_key)

        if include and not added_self:
            self.log(" adding this host ", True)
            new_host_keys.append(self.PUBLIC_KEY)

        return new_host_keys

    def get_key(self):
        self.log("Getting authorized_keys file ... ")

        self.get_file(self.AUTHORIZED_KEYS_REMOTE_PATH, self.TEMP_AUTHORIZED_KEYS_LOCAL_PATH)

        self.log_done()

    def put_key(self):
        self.log("Putting authorized_keys file ... ")

        self.put_file(self.TEMP_AUTHORIZED_KEYS_LOCAL_PATH, self.AUTHORIZED_KEYS_REMOTE_PATH)

        self.log_done()

    def remove_local_host_key(self):
        os.remove(self.TEMP_AUTHORIZED_KEYS_LOCAL_PATH)

    def login(self, host_name):
        self.open_ssh(host_name)
        self.open_sftp()

        self.ensure_ssh_folder()

    def open_ssh(self, host_name):
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.load_system_host_keys()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # TODO: setting the password here, should figure out a way to test the last and if it didn't work reprompt
        # based on the server that's trying to connect

        connected = False
        attempts = 0
        while attempts < 3 and not connected:
            try:
                self.log("Connecting to %s ... " % host_name, False)

                self.ssh_client.connect(host_name, username=self.username, password=self.password)

                self.log_done()
                connected = True
            except paramiko.AuthenticationException:
                self.line("FAILED")
                self.password = None

            if not connected:
                attempts += 1

                try:
                    self.set_password()
                except KeyboardInterrupt as e:
                    self.log("")
                    self.log("")
                    self.log("Aborting...")
                    sys.exit(1)

        if not connected:
            self.line()
            self.line()
            self.line("Sorry, you were unable to connect to host '%s'" % host_name)
            self.line()
            sys.exit(1)

    def open_sftp(self):
        self.log("Opening SFTP connection ... ", False)
        self.sftp_client = self.ssh_client.open_sftp()
        self.log_done()

    def disconnect(self):
        self.log("Closing SFTP ... ", False)
        self.sftp_client.close()
        self.log_done()

        self.log("Closing SSH ... ", False)
        self.ssh_client.close()
        self.log_done()

    def put_file(self, source, dest, mode=0600):
        self.sftp_client.put(source, dest)

        self.sftp_client.chmod(dest, mode)

    def read_key_file(self, file_path):
        contents = self.read_file(file_path)
        keys = []

        for key in contents:
            try:
                ssh_key = SSHKey(key.strip())
                keys.append(ssh_key)
            except KeyError:
                print "An invalid entry was found in this ssh file '%s'" % file_path

        return keys

    def save_host(self, host_name, include=True):
        self.log("Updating other hosts file ... ")

        contents = self.read_file(self.HOSTS_SYNCED_LOCAL_PATH)

        hosts = []

        for host in contents:
            if len(host) > 0 and not host in hosts:
                if include and host_name == host:
                    hosts.append(host_name)

                elif host_name != host and not host in hosts:
                    hosts.append(host)

        if include and not host_name in hosts:
            hosts.append(host_name)

        self.save_file(self.HOSTS_SYNCED_LOCAL_PATH, hosts)

        self.log_done()

    def set_password(self):
        if self.password is None:
            self.password = getpass.getpass()

    def line(self, msg=""):
        self.log(msg, True)

    def log(self, msg=None, new_line=False):
        if msg is None:
            msg = "=" * 80
            new_line = True

        elif len(msg) == 0:
            new_line = True

        if new_line:
            sys.stdout.write(msg + "\n")
        else:
            sys.stdout.write(msg)

    def log_done(self):
        self.log("DONE", True)

    def save_new_keys(self, new_host_keys):
        self.log("Saving new authorized_keys file ... ")
        file_contents = []

        for key in new_host_keys:
            file_contents.append(key.for_save())

        self.log_done()

    def read_file(self, file_path):
        contents = []

        if not os.path.exists(file_path):
            return contents

        open_file = open(file_path)

        while 1:

            line = open_file.readline().strip()

            if not line:
                break

            if len(line) > 0:
                contents.append(line)

        return contents

    def get_file(self, source, dest):
        if self.remote_path_exists(source):
            self.sftp_client.get(source, dest)
        else:
            self.save_file(dest, "")

    def save_file(self, path, contents):
        if type(contents) is list:
            contents = "\n".join(str(i) for i in contents)

        elif type(contents) is not str:
            raise Exception("contents is not a string or a list, it's a %s" % type(contents))

        myFile = open(path, 'w')
        myFile.write(contents + "\n")
        myFile.close()

    def register_all_hosts(self):

        self.line("Registering all hosts...")

        hosts = self.read_file(self.HOSTS_SYNCED_LOCAL_PATH)

        for host in hosts:
            self.register_host(host)

    def unregister_all_hosts(self):
        self.line("Unregistering all hosts...")

        hosts = self.read_file(self.HOSTS_SYNCED_LOCAL_PATH)

        for host in hosts:
            self.unregister_host(host)

    def ensure_ssh_folder(self):
        if not ".ssh" in self.sftp_client.listdir("."):
            self.sftp_client.mkdir(".ssh")
            self.line("Creating .ssh folder on host.")

        self.sftp_client.chmod(".ssh", 0700)

    def remote_path_exists(self, file_path):
        dirname = os.path.dirname(file_path)
        basename = os.path.basename(file_path)

        return basename in self.sftp_client.listdir(dirname)


if __name__ == "__main__":
    SyncProfile()
