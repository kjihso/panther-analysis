from gcp_base_helpers import get_k8s_info
from gcp_environment import PRODUCTION_PROJECT_IDS, rule_exceptions
from gcp_event_data import GkeEventData
from panther_base_helpers import deep_walk


def _parse_event_data(event):
    return GkeEventData(
        method_name=deep_walk(event, "protoPayload", "methodName"),
        namespace=deep_walk(get_k8s_info(event), "namespace", default="<NO NAMESPACE>"),
        namespaces=deep_walk(
            rule_exceptions, "gcp_k8s_exec_into_pod", "allowed_principals", "namespaces", default=[]
        ),
        pod=deep_walk(get_k8s_info(event), "pod", default=""),
        principal=deep_walk(get_k8s_info(event), "principal", default="<NO PRINCIPAL>"),
        principals=deep_walk(
            rule_exceptions, "gcp_k8s_exec_into_pod", "allowed_principals", "principals", default=[]
        ),
        project_id=deep_walk(get_k8s_info(event), "project_id", default="<NO PROJECT_ID>"),
        projects=deep_walk(
            rule_exceptions, "gcp_k8s_exec_into_pod", "allowed_principals", "projects", default=[]
        ),
        resource_name=deep_walk(event, "protoPayload", "resourceName"),
    )


def rule(event):
    parsed_event = _parse_event_data(event)

    # Defaults to False (no alert) unless method is exec and principal not allowed
    if not any(
        [
            parsed_event.method_name == "io.k8s.core.v1.pods.exec.create",
            parsed_event.resource_name,
        ]
    ):
        return False

    # rule_exceptions that are allowed temporarily are defined in gcp_environment.py
    # Some execs have principal which is long numerical UUID, appears to be k8s internals
    for principal in parsed_event.principals:
        if (
            principal in parsed_event.principals
            and (
                any(
                    [
                        parsed_event.namespace in parsed_event.namespaces,
                        parsed_event.namespaces == [],
                    ]
                ),
            )
            and (
                any([parsed_event.project_id in parsed_event.projects, parsed_event.projects == []])
            )
        ):
            if "@" not in parsed_event.principal:
                return False
    return True


def severity(event):
    parsed_event = _parse_event_data(event)
    if parsed_event.project_id in PRODUCTION_PROJECT_IDS:
        return "high"
    return "info"


def title(event):
    parsed_event = _parse_event_data(event)
    return f"Exec into pod namespace/{parsed_event.namespace}/pod/{parsed_event.pod} \
             by {parsed_event.principal} in {parsed_event.project_id}"


def alert_context(event):
    return get_k8s_info(event)
