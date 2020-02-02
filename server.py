"""
Webhook Queue - Simple, don-durable, multi-client webhook queueing server
Copyright (C) 2020  Andrew Story

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

from bottle import post, get, run, response, request, route, parse_auth
from typing import TypedDict, List, Optional
import hashlib
import binascii
import json
import hmac
import time
import random
import os


class NoneHash:
    def __init__(self):
        self.data = b""

    def update(self, content: bytes):
        self.data += content

    def digest(self) -> bytes:
        return self.data


# If you're looking to add more ways to authenticate webhook requests, scan for `More Auth Methods`

# If you're missing certain hash types, this is where to add them
hash_dict = {
    "plain": NoneHash,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}

# If you need more ways to authenticate a message (in place of HMAC), this is where you would add them
def apply_auth(strategy: str, key: str, message: bytes) -> str:
    global hash_dict
    decomposed = strategy.split("-")
    hasher = hash_dict[decomposed[1]]
    if decomposed[1] == "plain":
        raise StatusError(500, "Plain hasher is not permitted for the authentication method")
    if decomposed[0] == "hmac":
        authenticator = hmac.new(key.encode("utf-8"), digestmod=hasher)
    elif decomposed[0] == "hash":
        authenticator = hasher()
    else:
        raise StatusError(501, "Unknown auth strategy")
    authenticator.update(message)
    return authenticator.hexdigest()


class StatusError(Exception):
    def __init__(self, status_code: int, reason: str):
        self.status_code = status_code
        self.reason = reason


class RefreshError(StatusError):
    def __init__(self, reason: str):
        StatusError.__init__(self, 410, reason)


class QueueInfo(TypedDict, total=True):
    name: str
    last_message: int


class QueueMessage:
    def __init__(self, id: int, message: str):
        self.id: int = id
        self.message: str = message


class UserConf(TypedDict, total=True):
    name: str
    pass_hash: str
    queues: List[str]


class QueueAuthConf(TypedDict, total=False):
    key: str
    method: str
    header_name: str
    # More Auth Methods
    # Insert whatever additional auth fields you need here


class QueueConf(TypedDict, total=False):
    name: str
    whitelist_ip: List[str]
    auth: QueueAuthConf
    max_message_count: int
    max_message_size: int
    max_queue_size: int


class Conf(TypedDict, total=False):
    users: List[UserConf]
    queues: List[QueueConf]
    max_message_count: int
    max_message_size: int
    max_queue_size: int


def load_conf(fname: str) -> Conf:
    try:
        with open(fname, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print("No configuration file found. Writing example configuration to", fname)
        with open(fname, "w") as f:
            json.dump(
                fp=f,
                indent=4,
                obj={
                    "users": [{"name": "John Doe", "pass_hash": hash_pass("insecure", "plain"), "queues": ["foo"]}],
                    "queues": [{"name": "foo", "whitelist_ip": [], "auth": {"key": "12345", "method": "hmac-sha256", "header_name": "Foo-Auth"}}],
                    "max_message_count": 100,
                    "max_message_size": 2000,
                    "max_queue_size": 500000,
                },
            )
        exit(1)


def write_conf(fname: str, conf: Conf):
    temp = "{}.swap".format(fname)
    with open(temp, "w") as f:
        json.dump(conf, f, indent=4)
    os.rename(temp, fname)


class UserClient:
    def __init__(self, name: str, queue: str):
        self.name = name
        self.queue_name = queue
        global queues
        if queue not in queues:
            raise StatusError(404, "That queue does not exist")
        self.last_message = queues[queue].current_message


class User:
    def __init__(self, conf: UserConf):
        self.conf = conf
        self.name = conf["name"]
        self.clients = {}

    def listen(self, client: str, queue: str):
        if queue not in self.conf["queues"]:
            raise StatusError(404, "That queue is not available for listening")
        if client not in self.clients:
            self.clients[client] = UserClient(client, queue)
        else:
            raise StatusError(400, "You are already listening from that client")

    def unlisten(self, client: str):
        if client in self.clients:
            del self.clients[client]
        else:
            raise StatusError(404, "That client does not exist")

    def set_password(self, new_password: str):
        global config
        if len(new_password) < 6:
            raise StatusError(400, "Password must be at least 6 characters long")
        self.conf["pass_hash"] = hash_pass(new_password, salt=str(int(random.random() * 10000000000000)))
        write_conf(config_fname, config)


class Queue:
    def __init__(self, globalConf: "Conf", conf: "QueueConf"):
        def load(conf, key: str, default_value=None):
            if conf is not None and key in conf:
                return conf[key]
            return default_value

        self.name = load(conf, "name")
        self.max_message_count = load(conf, "max_message_count", load(globalConf, "max_message_count"))
        self.max_message_size = load(conf, "max_message_size", load(globalConf, "max_message_size"))
        self.max_queue_size = load(conf, "max_queue_size", load(globalConf, "max_queue_size"))
        self.whitelist_ip = load(conf, "whitelist_ip")

        auth = load(conf, "auth")
        self.auth_key = load(auth, "key")
        self.auth_method = load(auth, "method")
        self.auth_header_name = load(auth, "header_name")
        # More Auth Methods
        # Insert whatever new auth fields you need here

        self.current_message: int = 0
        self.messages: List[QueueMessage] = []
        self.queue_size = 0

        self.last_dropped_message = -1

    # More Auth Methods
    # Alter this function to handle other ways to authenticate a webhook request
    # Determines if the current Bottle request meets authentication requirements
    def auth(self, message: bytes) -> bool:
        if self.whitelist_ip is not None and len(self.whitelist_ip) > 0:
            if request.remote_addr not in self.whitelist_ip:
                return False
        if self.auth_method is None:
            return True
        if self.auth_header_name is not None and self.auth_key is not None:
            h = request.get_header(self.auth_header_name)
            authenticated = apply_auth(self.auth_method, self.auth_key, message)
            if authenticated == h:
                return True
        return False

    # Reads the current Bottle request as a message
    def push(self):
        message: bytes = request.body.read()
        authed = self.auth(message)

        if authed == False:
            raise StatusError(403, "Message was not properly authenticated")

        msg_size = len(message)
        self.current_message += 1
        if msg_size > self.max_message_size:
            self.last_dropped_message = self.current_message
            raise StatusError(413, "Message was too large")

        self.messages.append(QueueMessage(self.current_message, message.decode("utf-8")))
        self.queue_size += msg_size

        # Pop messages off the front until our queue size and message count fits in the max configured size
        while (self.queue_size > self.max_queue_size or len(self.messages) > self.max_message_count) and len(self.messages) > 0:
            popped = self.messages[0]
            self.queue_size -= len(popped.message)
            self.messages = self.messages[1:]

    def read(self, client: UserClient) -> List[dict]:
        if len(self.messages) == 0:
            return []

        if self.messages[0].id > client.last_message + 1:
            client.last_message = self.current_message
            raise RefreshError("It's been too long since you've read from the queue. As such, at least one message has been discarded. Please refresh your local state")
        if self.last_dropped_message > client.last_message:
            client.last_message = self.current_message
            raise RefreshError(
                "One or more messages have been dropped from the queue due to size constraints. If this continues to happen, consider reconfiguring your max queue sizes. Please refresh your local state"
            )
        estimate = self.current_message - client.last_message
        offset = 0
        idx = None
        if self.messages[0].id == client.last_message + 1:
            idx = 0
        else:
            for offset in range(len(self.messages)):
                for x in range(-1, 2, 2):  # get -1 and 1
                    check = estimate + offset * x
                    if check >= 0 and check < len(self.messages) and self.messages[check].id == client.last_message:
                        idx = check + 1
                        break
                else:
                    continue
                break
        client.last_message = self.current_message
        if idx == None:
            return []
        return [data.__dict__ for data in self.messages[idx:]]


def hash_pass(password: str, strategy: str = "sha512", salt: str = "") -> str:
    global hash_dict
    hasher = hash_dict[strategy]()
    hasher.update(password.encode("utf-8"))
    if salt != "" and strategy != "plain":
        hasher.update(salt.encode("utf-8"))
    digest = hasher.digest()
    if strategy != "plain":
        digest = binascii.hexlify(digest)
    return "{};{};{}".format(strategy, salt, digest.decode("ascii"))


def compare_pass(provided: str, actual: str) -> bool:
    decomposed = actual.split(";")
    if len(decomposed) != 3:
        raise StatusError(500, "Password hash on file is malformed")
    new_hash = hash_pass(provided, decomposed[0], decomposed[1])
    return new_hash == actual


def authenticate(config: Conf, username: str, password: str) -> Optional[UserConf]:
    for u in config["users"]:
        if u["name"] != username:
            continue
        if not compare_pass(password, u["pass_hash"]):
            continue
        return u
    return None


# Checks the request for valid authentication information in the Authorization header
def must_authenticate() -> User:
    global config, users
    auth = request.get_header("Authorization")
    username, password = parse_auth(auth)
    conf = authenticate(config, username, password)
    if conf == None:
        raise StatusError(403, "Unrecognized login")
    return users[username]


started_at = int(time.time())
config_fname = "options.conf"
config = load_conf(config_fname)
queues = {}
users = {}

for q in config["queues"]:
    new_queue = Queue(config, q)
    queues[new_queue.name] = new_queue
for u in config["users"]:
    new_user = User(u)
    users[new_user.name] = new_user


@post("/q/<name>")
def enqueue(name):
    try:
        if name not in queues:
            return
        q = queues[name]
        q.push()
        return
    except RefreshError as e:
        response.status = e.status_code
        return json.dumps({"refresh": True, "message": e.reason})
    except StatusError as e:
        response.status = e.status_code
        return json.dumps({"refresh": False, "message": e.reason})
    except Exception as e:
        response.status = 500
        return json.dumps({"refresh": False, "message": " ".join(e.args)})


@get("/read/<client>")
def fetch(client):
    try:
        user = must_authenticate()
        if client not in user.clients:
            raise ValueError("You are not currently listening on that client")
        c = user.clients[client]
        if c.queue_name not in queues:
            raise ValueError("Unknown queue '{}'".format(c.queue_name))
        q = queues[c.queue_name]
        msgs = q.read(c)
        result = {"time": str(started_at), "messages": msgs, "current_message": q.current_message}
        return json.dumps(result)
    except RefreshError as e:
        response.status = e.status_code
        return json.dumps({"refresh": True, "message": e.reason})
    except StatusError as e:
        response.status = e.status_code
        return json.dumps({"refresh": False, "message": e.reason})
    except Exception as e:
        response.status = 500
        return json.dumps({"refresh": False, "message": " ".join(e.args)})


@get("/listen/<client>/<queue>")
def listen(client, queue):
    try:
        user = must_authenticate()
        user.listen(client, queue)

        return ""
    except RefreshError as e:
        response.status = e.status_code
        return json.dumps({"refresh": True, "message": e.reason})
    except StatusError as e:
        response.status = e.status_code
        return json.dumps({"refresh": False, "message": e.reason})
    except Exception as e:
        response.status = 500
        return json.dumps({"refresh": False, "message": " ".join(e.args)})


@get("/unlisten/<client>")
def unlisten(client):
    try:
        user = must_authenticate()
        user.unlisten(client)

        return ""
    except RefreshError as e:
        response.status = e.status_code
        return json.dumps({"refresh": True, "message": e.reason})
    except StatusError as e:
        response.status = e.status_code
        return json.dumps({"refresh": False, "message": e.reason})
    except Exception as e:
        response.status = 500
        return json.dumps({"refresh": False, "message": " ".join(e.args)})


@post("/setPassword")
def set_password():
    try:
        user = must_authenticate()
        body = json.load(request.body)
        user.set_password(body["password"])

        return ""
    except RefreshError as e:
        response.status = e.status_code
        return json.dumps({"refresh": True, "message": e.reason})
    except StatusError as e:
        response.status = e.status_code
        return json.dumps({"refresh": False, "message": e.reason})
    except Exception as e:
        response.status = 500
        return json.dumps({"refresh": False, "message": " ".join(e.args)})


@route("/time")
def get_time():
    return "{}".format(started_at)


if __name__ == "__main__":
    run(host="localhost", port=8080)
