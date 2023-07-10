from dataclasses import dataclass
from typing import Optional


# pylint: disable=too-many-instance-attributes
@dataclass
class GkeEventData:
    """Dataclass to hold GKE-specific event data"""

    method_name: Optional[str] = None
    namespace: Optional[str] = None
    namespaces: Optional[list[str]] = None
    pod: Optional[str] = None
    principal: Optional[str] = None
    principals: Optional[list[str]] = None
    project_id: Optional[str] = None
    projects: Optional[list[str]] = None
    resource_name: Optional[str] = None
