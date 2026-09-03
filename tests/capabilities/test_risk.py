from uuid import uuid4

import pytest

from vyuu_gateway.capabilities.risk import classify_tool_risk
from vyuu_gateway.db.models import (
    McpCapabilityKind,
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    RiskCategory,
)


def _server(display_name: str = "github") -> McpServer:
    return McpServer(
        id=uuid4(),
        tenant_id=uuid4(),
        display_name=display_name,
        source_type=McpServerSourceType.NPM,
        source_location="@example/server",
        transport=McpTransport.STDIO,
        args=[],
        registered_by=uuid4(),
        health_status=McpServerHealthStatus.UNKNOWN,
    )


# --- Required examples from the task spec ---------------------------------------------------


def test_list_repos_classifies_as_read() -> None:
    assert classify_tool_risk(name="list_repos") == RiskCategory.READ


def test_delete_file_classifies_as_delete() -> None:
    assert classify_tool_risk(name="delete_file") == RiskCategory.DELETE


def test_run_command_classifies_as_execute() -> None:
    assert classify_tool_risk(name="run_command") == RiskCategory.EXECUTE


def test_send_email_classifies_as_data_export() -> None:
    assert classify_tool_risk(name="send_email") == RiskCategory.DATA_EXPORT


def test_get_secret_classifies_as_credential_access() -> None:
    assert classify_tool_risk(name="get_secret") == RiskCategory.CREDENTIAL_ACCESS


# --- READ ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "list_repos",
        "list_objects",
        "get_user",
        "read_file",
        "search_issues",
        "describe_table",
        "show_status",
        "view_dashboard",
        "query_select",
        "head_object",
    ],
)
def test_read_keywords(name: str) -> None:
    assert classify_tool_risk(name=name) == RiskCategory.READ


# --- WRITE -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "create_issue",
        "update_record",
        "write_file",
        "edit_document",
        "patch_resource",
        "put_object",
        "add_label",
        "insert_row",
        "save_draft",
        "rename_branch",
    ],
)
def test_write_keywords(name: str) -> None:
    assert classify_tool_risk(name=name) == RiskCategory.WRITE


# --- DELETE ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "delete_file",
        "destroy_resource",
        "remove_label",
        "drop_table",
        "purge_cache",
        "unlink_file",
        "wipe_database",
    ],
)
def test_delete_keywords(name: str) -> None:
    assert classify_tool_risk(name=name) == RiskCategory.DELETE


# --- EXECUTE ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "run_command",
        "execute_query",
        "exec_shell",
        "invoke_lambda",
        "spawn_process",
        "eval_code",
        "shell_exec",
    ],
)
def test_execute_keywords(name: str) -> None:
    assert classify_tool_risk(name=name) == RiskCategory.EXECUTE


# --- NETWORK ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "http_request",
        "http_get",
        "http_post",
        "fetch_url",
        "download_file",
        "ping_host",
        "dns_lookup",
    ],
)
def test_network_keywords(name: str) -> None:
    assert classify_tool_risk(name=name) == RiskCategory.NETWORK


# --- CREDENTIAL_ACCESS -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "get_secret",
        "list_secrets",
        "read_credential",
        "fetch_token",
        "get_api_key",
        "rotate_password",
        "describe_vault",
        "get_private_key",
    ],
)
def test_credential_access_keywords(name: str) -> None:
    assert classify_tool_risk(name=name) == RiskCategory.CREDENTIAL_ACCESS


def test_credential_access_dominates_read_prefix() -> None:
    # `get_secret` would otherwise match READ via "get".
    assert classify_tool_risk(name="get_secret") == RiskCategory.CREDENTIAL_ACCESS


def test_credential_access_dominates_write_prefix() -> None:
    # `update_password` would otherwise match WRITE via "update".
    assert classify_tool_risk(name="update_password") == RiskCategory.CREDENTIAL_ACCESS


# --- DATA_EXPORT -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "send_email",
        "send_sms",
        "send_message",
        "post_message",
        "publish_event",
        "upload_artifact",
        "export_report",
        "broadcast_alert",
        "share_document",
    ],
)
def test_data_export_keywords(name: str) -> None:
    assert classify_tool_risk(name=name) == RiskCategory.DATA_EXPORT


def test_data_export_dominates_write() -> None:
    # `send_email` would otherwise match WRITE via "send" (it does not, but
    # `update_webhook` would otherwise match WRITE via "update").
    assert classify_tool_risk(name="update_webhook") == RiskCategory.DATA_EXPORT


# --- ADMIN -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "grant_role",
        "revoke_role",
        "assign_role",
        "set_policy",
        "update_policy",
        "set_acl",
        "create_user",
        "delete_user",
        "disable_user",
        "chmod",
        "chown",
        "sudo_run",
    ],
)
def test_admin_keywords(name: str) -> None:
    assert classify_tool_risk(name=name) == RiskCategory.ADMIN


def test_admin_dominates_delete() -> None:
    # `delete_user` would otherwise match DELETE via "delete".
    assert classify_tool_risk(name="delete_user") == RiskCategory.ADMIN


# --- UNKNOWN / fallthrough -------------------------------------------------------------------


def test_unknown_when_no_keywords_match() -> None:
    assert classify_tool_risk(name="zzz") == RiskCategory.UNKNOWN


def test_resources_and_prompts_are_unknown_regardless_of_name() -> None:
    assert (
        classify_tool_risk(name="list_repos", kind=McpCapabilityKind.RESOURCE)
        == RiskCategory.UNKNOWN
    )
    assert (
        classify_tool_risk(name="run_command", kind=McpCapabilityKind.PROMPT)
        == RiskCategory.UNKNOWN
    )


# --- Description and schema as secondary signals ---------------------------------------------


def test_description_supplies_signal_when_name_is_generic() -> None:
    assert (
        classify_tool_risk(
            name="op",
            description="Delete a file from the bucket.",
        )
        == RiskCategory.DELETE
    )


def test_input_schema_property_names_supply_signal() -> None:
    assert (
        classify_tool_risk(
            name="op",
            input_schema={
                "type": "object",
                "properties": {"command": {"type": "string"}},
            },
        )
        == RiskCategory.EXECUTE
    )


# --- Server metadata fallback ----------------------------------------------------------------


def test_server_metadata_used_only_when_primary_signals_silent() -> None:
    server = _server(display_name="vault")
    # Primary signal (name) classifies, server metadata ignored.
    assert (
        classify_tool_risk(name="list_repos", server=server) == RiskCategory.READ
    )


def test_server_metadata_drives_classification_for_generic_tool_names() -> None:
    server = _server(display_name="vault")
    assert (
        classify_tool_risk(name="op", server=server)
        == RiskCategory.CREDENTIAL_ACCESS
    )


def test_server_metadata_does_not_pollute_unrelated_tools() -> None:
    server = _server(display_name="github")
    assert classify_tool_risk(name="op", server=server) == RiskCategory.UNKNOWN


# --- Case insensitivity ----------------------------------------------------------------------


def test_classification_is_case_insensitive() -> None:
    assert classify_tool_risk(name="DELETE_FILE") == RiskCategory.DELETE


def test_camelcase_names_are_split_on_word_boundaries() -> None:
    assert classify_tool_risk(name="GetSecret") == RiskCategory.CREDENTIAL_ACCESS
    assert classify_tool_risk(name="deleteFile") == RiskCategory.DELETE
    assert classify_tool_risk(name="runCommand") == RiskCategory.EXECUTE
