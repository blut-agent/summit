from .cors_reflect import CorsReflectionCheck
from .crlf import CrlfInjectionCheck
from .enumeration import EnumerationCheck
from .host_header import HostHeaderInjectionCheck
from .open_redirect import OpenRedirectCheck
from .os_command import OsCommandInjectionCheck
from .path_traversal import PathTraversalCheck
from .sqli import SqliBooleanCheck, SqliErrorCheck
from .sqli_time import SqliTimeCheck
from .ssti import SstiCheck
from .waf_bypass import WafBypassCheck
from .xss import XssReflectCheck

ALL_CHECKS = [
    SqliErrorCheck(),
    SqliBooleanCheck(),
    SqliTimeCheck(),
    XssReflectCheck(),
    WafBypassCheck(),
    OsCommandInjectionCheck(),
    SstiCheck(),
    CrlfInjectionCheck(),
    HostHeaderInjectionCheck(),
    CorsReflectionCheck(),
    EnumerationCheck(),
    OpenRedirectCheck(),
    PathTraversalCheck(),
]
