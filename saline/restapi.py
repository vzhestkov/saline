import cgi
import logging
import os
import ssl
import tornado
import tornado.gen
import tornado.log
import tornado.web

from fnmatch import fnmatch
from threading import Thread
from time import time, sleep
from tornado.escape import native_str
from tornado.ioloop import IOLoop
from tornado.iostream import StreamClosedError
from uuid import uuid4

from salt.auth import Resolver as AuthResolver
from salt.transport.ipc import IPCMessageClient, IPCMessageSubscriber
from salt.utils.asynchronous import current_ioloop as ctx_current_ioloop
from salt.utils.json import import_json, loads as json_loads, dumps as json_dumps
from salt.utils.yaml import safe_dump as yaml_safe_dump, safe_load as yaml_safe_load


log = logging.getLogger(__name__)

_json = import_json()

AUTH_TOKEN_HEADER = "X-Auth-Token"
AUTH_COOKIE_NAME = "saline_session_id"


def _json_dumps(obj, **kwargs):
    """
    Invoke salt.utils.json.dumps using the alternate json module loaded using
    salt.utils.json.import_json(). This ensures that we properly encode any
    strings in the object before we perform the serialization.
    """
    return json_dumps(obj, _json_module=_json, **kwargs)


class SalineChannels:
    def __init__(self, opts):
        self.opts = opts
        self.metrics_buf = None
        self.metrics_last = None
        self.metrics_timeout = opts.get("metrics_timeout", 120)
        self.resp_buf = []
        self.resp_refs = {}

    def run_channels(self):
        self.io_loop = IOLoop.current()
        self.pub_uri = os.path.join(self.opts["sock_dir"], "publisher.ipc")
        self.pull_uri = os.path.join(self.opts["sock_dir"], "puller.ipc")
        with ctx_current_ioloop(self.io_loop):
            self.subscriber = IPCMessageSubscriber(self.pub_uri, io_loop=self.io_loop)
            self.subscriber.callbacks.add(self.channel_event_handler)
            for _ in range(5):
                try:
                    self.subscriber.connect(
                        timeout=1, callback=self.subscriber_connected
                    )
                    break
                except StreamClosedError:
                    sleep(1)
            self.io_loop.add_callback(self.subscriber.read_async)
            self.pusher = IPCMessageClient(self.pull_uri, io_loop=self.io_loop)
            for _ in range(5):
                try:
                    self.pusher.connect(timeout=1, callback=self.pusher_connected)
                    break
                except StreamClosedError:
                    sleep(1)

    def subscriber_connected(self, _):
        log.debug("Connected to Saline publisher channel")
        self.metrics_buf = ""
        self.metrics_last = time()

    def pusher_connected(self, _):
        log.debug("Connected to Saline puller channel")

    @tornado.gen.coroutine
    def send(self, msg, timeout=10):
        ref = None
        if isinstance(msg, dict) and "_ref" not in msg:
            msg["_ref"] = ref = str(uuid4())
        self.pusher.send(msg)
        timeout_on = time() + timeout
        timed_out = False
        while not timed_out:
            yield tornado.gen.sleep(0.1)
            if ref is not None:
                ret = self.resp_refs.pop(ref, None)
            else:
                try:
                    ret = self.resp_buf.pop(0)
                except IndexError:
                    ret = None
            if ret is not None:
                raise tornado.gen.Return(ret)
            timed_out = time() > timeout_on

    @tornado.gen.coroutine
    def channel_event_handler(self, raw):
        log.trace("Received from Saline publisher: %s", raw)
        if "metrics" in raw:
            self.metrics_buf = raw["metrics"]
            self.metrics_last = time()
        elif isinstance(raw, dict) and "_ref" in raw:
            self.resp_refs[raw["_ref"]] = raw
        else:
            self.resp_buf.append(raw)


class BaseAPIHandler(tornado.web.RequestHandler):  # pylint: disable=W0223
    ct_out_map = (
        ("application/json", _json_dumps),
        ("application/x-yaml", yaml_safe_dump),
    )

    def prepare(self):
        """
        Run before get/posts etc. Pre-flight checks:
            - verify that we can speak back to them (compatible accept header)
        """
        # Find an acceptable content-type
        accept_header = self.request.headers.get("Accept", "*/*")
        # Ignore any parameter, including q (quality) one
        parsed_accept_header = [
            cgi.parse_header(h)[0] for h in accept_header.split(",")
        ]

        def find_acceptable_content_type(parsed_accept_header):
            for media_range in parsed_accept_header:
                for content_type, dumper in self.ct_out_map:
                    if fnmatch(content_type, media_range):
                        return content_type, dumper
            return None, None

        content_type, dumper = find_acceptable_content_type(parsed_accept_header)

        # better return message?
        if not content_type:
            self.send_error(406)

        self.content_type = content_type
        self.dumper = dumper

        self.request_payload = self.deserialize(self.request.body)

    def serialize(self, data):
        """
        Serlialize the output based on the Accept header
        """
        self.set_header("Content-Type", self.content_type)

        return self.dumper(data)

    def deserialize(self, data):
        """
        Deserialize the data based on request content type headers
        """
        ct_in_map = {
            "application/json": json_loads,
            "application/x-yaml": yaml_safe_load,
            "text/yaml": yaml_safe_load,
            "text/plain": json_loads,
        }

        nstr = native_str(data)
        if nstr == "":
            return None
        try:
            # Use cgi.parse_header to correctly separate parameters from value
            value, parameters = cgi.parse_header(self.request.headers["Content-Type"])
            return ct_in_map[value](nstr)
        except KeyError:
            self.send_error(406)
        except ValueError:
            self.send_error(400)

    def options(self, *args, **kwargs):
        """
        Return CORS headers for preflight requests
        """
        # Allow X-Auth-Token in requests
        request_headers = self.request.headers.get("Access-Control-Request-Headers")
        allowed_headers = request_headers.split(",")

        # Filter allowed header here if needed.

        # Allow request headers
        self.set_header("Access-Control-Allow-Headers", ",".join(allowed_headers))

        # Allow X-Auth-Token in responses
        self.set_header("Access-Control-Expose-Headers", "X-Auth-Token")

        # Allow all methods
        self.set_header("Access-Control-Allow-Methods", "OPTIONS, GET, POST")

        self.set_status(204)
        self.finish()

    @property
    def token(self):
        """
        The token used for the request
        """
        # find the token (cookie or headers)
        if AUTH_TOKEN_HEADER in self.request.headers:
            return self.request.headers[AUTH_TOKEN_HEADER]
        else:
            return self.get_cookie(AUTH_COOKIE_NAME)

    def _verify_auth(self):
        """
        Verify if the token is valid
        """
        if self.token:
            token_dict = self.application.auth_resolver.get_token(self.token)
            if token_dict and token_dict.get("expire", 0) > time():
                self.request.saline_user = token_dict.get("name")
                return True
        return False


class LoginHandler(BaseAPIHandler):  # pylint: disable=W0223
    def get(self):  # pylint: disable=arguments-differ
        self.set_status(401)
        self.set_header("WWW-Authenticate", "Session")

        ret = {"status": "401 Unauthorized", "return": "Please log in"}

        self.write(self.serialize(ret))

    def post(self):  # pylint: disable=arguments-differ
        try:
            if not isinstance(self.request_payload, dict):
                self.send_error(400)
                return

            creds = {
                "username": self.request_payload["username"],
                "password": self.request_payload["password"],
                "eauth": self.request_payload["eauth"],
            }
        # if any of the args are missing, its a bad request
        except KeyError:
            self.send_error(400)
            return

        token_dict = self.application.auth_resolver.mk_token(creds)
        if "token" not in token_dict:
            self.set_status(401)
            ret = {
                "status": "401 Unauthorized",
                "return": "The specified credentials are incorrect",
            }
            self.write(self.serialize(ret))
            return
        self.set_cookie(AUTH_COOKIE_NAME, token_dict["token"])

        ret = {
            "return": [
                {
                    "token": token_dict["token"],
                    "expire": token_dict["expire"],
                    "start": token_dict["start"],
                    "user": token_dict["name"],
                    "eauth": token_dict["eauth"],
                }
            ]
        }

        self.request.saline_user = token_dict.get("name")

        self.write(self.serialize(ret))


class MetricsHandler(tornado.web.RequestHandler):  # pylint: disable=W0223
    def get(self, _):  # pylint: disable=arguments-differ
        if (
            time() - self.application.channels.metrics_last
            > self.application.channels.metrics_timeout
        ):
            log.error(
                "No metrics update for more than %s sec.",
                self.application.channels.metrics_timeout,
            )
            self.send_error(500)
            return
        elif self.application.channels.metrics_buf is not None:
            self.set_header("Cache-Control", "no-cache")
            self.set_header("Content-Type", "text/plain;version=0.0.4;charset=utf-8")
            self.write(self.application.channels.metrics_buf)

        self.finish()


class StatsHandler(BaseAPIHandler):  # pylint: disable=W0223
    @tornado.gen.coroutine
    def get(self, rel_path=None):  # pylint: disable=arguments-differ
        if not self._verify_auth():
            self.redirect("/login")
            return
        if rel_path is None:
            rel_path = "TOP"
        if rel_path.startswith("/"):
            rel_path = rel_path[1:]
        ret = yield self.application.channels.send({"cmd": "stats", "stats": rel_path})
        self.write(self.serialize(ret))


def get_app(opts):
    """
    Returns a Tornado Web APP
    """

    restapi_opts = opts.get("restapi", {})

    paths = [
        (r"/metrics(/.*)?", MetricsHandler),
        (r"/login", LoginHandler),
        (r"/stats(/.*)?", StatsHandler),
    ]

    tornado_access_log = None
    access_log_file = restapi_opts.get("log_access_file")
    if access_log_file is not None:
        access_log = logging.getLogger("tornado.access")
        access_log.propagate = False
        access_log.setLevel(logging.INFO)
        access_log_handler = logging.FileHandler(access_log_file)
        formatter = logging.Formatter(
            restapi_opts.get(
                "log_access_format",
                "%(asctime)s %(message)s",
            )
        )
        access_log_handler.setFormatter(formatter)
        access_log.addHandler(access_log_handler)
        tornado.log.enable_pretty_logging(logger=access_log)

        def tornado_access_log(handler):
            status = handler.get_status()
            request_time = 1000.0 * handler.request.request_time()
            log_level = logging.INFO
            if status >= 500:
                log_level = logging.ERROR
            elif status >= 400:
                log_level = logging.WARNING
            access_log.log(
                log_level,
                '%s - %s "%s %s" %d %s "%s" %.2fms',
                handler.request.remote_ip,
                (
                    handler.request.saline_user
                    if hasattr(handler.request, "saline_user")
                    and handler.request.saline_user
                    else "-"
                ),
                handler.request.method,
                handler.request.uri,
                status,
                handler._headers.get("Content-Length", "") or "-",
                handler.request.headers.get("User-Agent", "") or "-",
                request_time,
            )

    app = tornado.web.Application(
        paths,
        log_function=tornado_access_log,
        debug=restapi_opts.get("debug", False),
    )

    app.channels = SalineChannels(opts)

    auth_opts = {
        "interface": opts.get("master_interface", "0.0.0.0"),
        "ret_port": opts.get("master_ret_port", 4506),
        "cython_enable": False,
    }
    app.auth_resolver = AuthResolver(auth_opts)

    return app


def start(opts):
    """
    Start Tornado Web APP
    """

    restapi_opts = opts.get("restapi", {})

    if "num_processes" not in restapi_opts:
        restapi_opts["num_processes"] = 1

    if restapi_opts["num_processes"] > 1 and restapi_opts.get("debug", False) is True:
        raise Exception(
            "Tornado's debug implementation is not compatible with multiprocess. "
            "Either disable debug, or set num_processes to 1."
        )

    # the kwargs for the HTTPServer
    kwargs = {}
    if not restapi_opts.get("disable_ssl", False):
        if "ssl_crt" not in restapi_opts:
            log.error(
                "Not starting '%s'. Options 'ssl_crt' and "
                "'ssl_key' are required if SSL is not disabled.",
            )

            return None
        # cert is required, key may be optional
        # https://docs.python.org/2/library/ssl.html#ssl.wrap_socket
        ssl_opts = {
            "certfile": restapi_opts["ssl_crt"],
            "ssl_version": ssl.PROTOCOL_TLS_SERVER,
        }
        if not os.path.exists(ssl_opts["certfile"]):
            raise Exception(f"Could not find a certificate: {ssl_opts['certfile']}")
        if restapi_opts.get("ssl_key", False):
            ssl_opts.update({"keyfile": restapi_opts["ssl_key"]})
            if not os.path.exists(ssl_opts["keyfile"]):
                raise Exception(
                    f"Could not find a certificate key: {ssl_opts['keyfile']}"
                )
        kwargs["ssl_options"] = ssl_opts

    import tornado.httpserver

    log.debug("Creating Tornado HTTP server ...")
    app = get_app(opts)
    http_server = tornado.httpserver.HTTPServer(app, **kwargs)
    listen_port = restapi_opts.get("port", 8216)
    listen_host = restapi_opts.get("host", "0.0.0.0")
    try:
        log.debug("Binding Tornado HTTP server to %s:%s ...", listen_host, listen_port)
        http_server.bind(
            listen_port,
            address=listen_host,
            backlog=restapi_opts.get("backlog", 128),
        )
        log.debug("Starting Tornado HTTP server ...")
        http_server.start(restapi_opts["num_processes"])
    except Exception:  # pylint: disable=broad-except
        log.error(
            "Tornado Web APP unable to bind to %s:%s",
            listen_host,
            listen_port,
            exc_info=True,
        )
        raise SystemExit(1)

    app.channels.run_channels()
    try:
        IOLoop.current().start()
    except KeyboardInterrupt:
        raise SystemExit(0)


def stop():
    """
    Start Tornado Web APP
    """

    try:
        IOLoop.current().stop()
    except KeyboardInterrupt:
        raise SystemExit(0)
