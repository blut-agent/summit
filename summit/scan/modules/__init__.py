from .cors_reflect import CorsReflectionCheck
from .host_header import HostHeaderInjectionCheck
from .open_redirect import OpenRedirectCheck
from .path_traversal import PathTraversalCheck
from .sqli import SqliBooleanCheck, SqliErrorCheck
from .waf_bypass import WafBypassCheck
from .xss import XssReflectCheck

ALL_CHECKS = [
    SqliErrorCheck(),
    SqliBooleanCheck(),
    XssReflectCheck(),
    WafBypassCheck(),
    HostHeaderInjectionCheck(),
    CorsReflectionCheck(),
    OpenRedirectCheck(),
    PathTraversalCheck(),
]
