from .cors_reflect import CorsReflectionCheck
from .crlf import CrlfInjectionCheck
from .enumeration import EnumerationCheck
from .format_string import FormatStringCheck
from .host_header import HostHeaderInjectionCheck
from .hpp import HppCheck
from .jwt_security import JwtSecurityCheck
from .ldap import LdapInjectionCheck
from .nosql import NosqlInjectionCheck
from .open_redirect import OpenRedirectCheck
from .os_command import OsCommandInjectionCheck
from .path_traversal import PathTraversalCheck
from .session_fixation import SessionFixationCheck
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
    NosqlInjectionCheck(),
    LdapInjectionCheck(),
    FormatStringCheck(),
    HostHeaderInjectionCheck(),
    CorsReflectionCheck(),
    EnumerationCheck(),
    SessionFixationCheck(),
    JwtSecurityCheck(),
    OpenRedirectCheck(),
    PathTraversalCheck(),
    HppCheck(),
]
