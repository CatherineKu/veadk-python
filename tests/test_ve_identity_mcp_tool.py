# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Unit tests for VeIdentityMcpTool."""

import pytest
from unittest.mock import Mock, AsyncMock, patch

from google.adk.auth.auth_credential import (
    AuthCredential,
    AuthCredentialTypes,
    HttpAuth,
    HttpCredentials,
)
from veadk.integrations.ve_identity.mcp_tool import VeIdentityMcpTool
from veadk.integrations.ve_identity.auth_config import api_key_auth, oauth2_auth
from veadk.integrations.ve_identity.auth_mixins import AuthRequiredException
from veadk.integrations.ve_identity.identity_client import IdentityClient
from veadk.integrations.ve_identity.models import WorkloadToken
from veadk.utils.auth import VE_TIP_TOKEN_HEADER


class TestVeIdentityMcpToolInit:
    """Tests for VeIdentityMcpTool initialization."""

    @patch("veadk.integrations.ve_identity.auth_mixins.IdentityClient")
    def test_init_with_api_key_auth(self, mock_identity_client):
        """Test initializing with API key auth config."""
        mcp_tool = Mock()
        mcp_tool.name = "test_tool"
        mcp_tool.description = "Test tool description"

        mcp_session_manager = Mock()
        config = api_key_auth("test-provider")

        tool = VeIdentityMcpTool(
            mcp_tool=mcp_tool,
            mcp_session_manager=mcp_session_manager,
            auth_config=config,
        )

        assert tool.name == "test_tool"
        assert tool.description == "Test tool description"
        assert tool._mcp_tool == mcp_tool
        assert tool._mcp_session_manager == mcp_session_manager

    @patch("veadk.integrations.ve_identity.auth_mixins.IdentityClient")
    def test_init_with_oauth2_auth(self, mock_identity_client):
        """Test initializing with OAuth2 auth config."""
        mcp_tool = Mock()
        mcp_tool.name = "github_tool"
        mcp_tool.description = "GitHub tool"

        mcp_session_manager = Mock()
        config = oauth2_auth(provider_name="github", scopes=["repo"], auth_flow="M2M")

        tool = VeIdentityMcpTool(
            mcp_tool=mcp_tool,
            mcp_session_manager=mcp_session_manager,
            auth_config=config,
        )

        assert tool.name == "github_tool"
        assert tool._auth_config == config

    def test_init_with_none_mcp_tool(self):
        """Test that initialization fails with None mcp_tool."""
        mcp_session_manager = Mock()
        config = api_key_auth("test-provider")

        with pytest.raises(ValueError, match="mcp_tool cannot be None"):
            VeIdentityMcpTool(
                mcp_tool=None,
                mcp_session_manager=mcp_session_manager,
                auth_config=config,
            )

    def test_init_with_none_mcp_session_manager(self):
        """Test that initialization fails with None mcp_session_manager."""
        mcp_tool = Mock()
        mcp_tool.name = "test_tool"
        mcp_tool.description = "Test"
        config = api_key_auth("test-provider")

        with pytest.raises(ValueError, match="mcp_session_manager cannot be None"):
            VeIdentityMcpTool(
                mcp_tool=mcp_tool, mcp_session_manager=None, auth_config=config
            )


class TestVeIdentityMcpToolRunAsync:
    """Tests for VeIdentityMcpTool.run_async method."""

    @pytest.mark.asyncio
    @patch("veadk.integrations.ve_identity.auth_mixins.IdentityClient")
    async def test_run_async_with_api_key(self, mock_identity_client):
        """Test run_async with API key authentication."""
        mcp_tool = Mock()
        mcp_tool.name = "test_tool"
        mcp_tool.description = "Test"

        mcp_session_manager = Mock()
        config = api_key_auth("test-provider")

        tool = VeIdentityMcpTool(
            mcp_tool=mcp_tool,
            mcp_session_manager=mcp_session_manager,
            auth_config=config,
        )

        # Mock the run_with_identity_auth method
        tool.run_with_identity_auth = AsyncMock(return_value="Result: test-key")

        tool_context = Mock()
        result = await tool.run_async(args={}, tool_context=tool_context)

        assert result == "Result: test-key"
        tool.run_with_identity_auth.assert_called_once()

    @pytest.mark.asyncio
    @patch("veadk.integrations.ve_identity.auth_mixins.IdentityClient")
    async def test_run_async_handles_auth_required_exception(
        self, mock_identity_client
    ):
        """Test that run_async handles AuthRequiredException."""
        mcp_tool = Mock()
        mcp_tool.name = "test_tool"
        mcp_tool.description = "Test"

        mcp_session_manager = Mock()
        config = oauth2_auth(
            provider_name="github", scopes=["repo"], auth_flow="USER_FEDERATION"
        )

        tool = VeIdentityMcpTool(
            mcp_tool=mcp_tool,
            mcp_session_manager=mcp_session_manager,
            auth_config=config,
        )

        # Mock the run_with_identity_auth to raise AuthRequiredException
        auth_exception = AuthRequiredException("Please authorize")
        tool.run_with_identity_auth = AsyncMock(side_effect=auth_exception)

        tool_context = Mock()
        result = await tool.run_async(args={}, tool_context=tool_context)

        assert result == "Please authorize"

    @pytest.mark.asyncio
    async def test_run_async_exchanges_inbound_auth_for_mcp_tip_header(self):
        """Test MCP tool calls exchange inbound user JWT into X-Ve-TIP-Token."""
        mcp_tool = Mock()
        mcp_tool.name = "sequentialthinking"
        mcp_tool.description = "Test"

        session = Mock()
        session.call_tool = AsyncMock(return_value="ok")
        mcp_session_manager = Mock()
        mcp_session_manager.create_session = AsyncMock(return_value=session)

        identity_client = IdentityClient(
            access_key="test-ak",
            secret_key="test-sk",
            enable_vefaas_iam_fallback=False,
        )
        identity_client.get_workload_access_token = Mock(
            return_value=WorkloadToken(
                workload_access_token="workload-tip-token",
                expires_at=4102444800,
            )
        )
        tool = VeIdentityMcpTool(
            mcp_tool=mcp_tool,
            mcp_session_manager=mcp_session_manager,
            auth_config=api_key_auth(
                "test-provider",
                identity_client=identity_client,
            ),
            propagate_user_token_as_tip=True,
            tip_workload_name="mcp-authz-workload",
        )

        inbound_credential = AuthCredential(
            auth_type=AuthCredentialTypes.HTTP,
            http=HttpAuth(
                scheme="bearer",
                credentials=HttpCredentials(token="user-pool-jwt"),
            ),
        )
        tool_context = _mock_tool_context(inbound_credential=inbound_credential)
        service_credential = AuthCredential(
            auth_type=AuthCredentialTypes.API_KEY,
            api_key="Bearer mcp-service-key",
        )

        result = await tool._run_async_impl(
            args={"thought": "check auth"},
            tool_context=tool_context,
            credential=service_credential,
        )

        assert result == "ok"
        identity_client.get_workload_access_token.assert_called_once_with(
            workload_name="mcp-authz-workload",
            user_token="user-pool-jwt",
            user_id="user-123",
        )
        mcp_session_manager.create_session.assert_called_once_with(
            headers={
                "Authorization": "Bearer mcp-service-key",
                VE_TIP_TOKEN_HEADER: "workload-tip-token",
            }
        )
        session.call_tool.assert_awaited_once_with(
            "sequentialthinking",
            arguments={"thought": "check auth"},
        )

    @pytest.mark.asyncio
    async def test_run_async_skips_tip_header_without_inbound_auth(self):
        """Test MCP tool calls keep service auth only when no inbound user JWT exists."""
        mcp_tool = Mock()
        mcp_tool.name = "sequentialthinking"
        mcp_tool.description = "Test"

        session = Mock()
        session.call_tool = AsyncMock(return_value="ok")
        mcp_session_manager = Mock()
        mcp_session_manager.create_session = AsyncMock(return_value=session)

        identity_client = IdentityClient(
            access_key="test-ak",
            secret_key="test-sk",
            enable_vefaas_iam_fallback=False,
        )
        identity_client.get_workload_access_token = Mock()
        tool = VeIdentityMcpTool(
            mcp_tool=mcp_tool,
            mcp_session_manager=mcp_session_manager,
            auth_config=api_key_auth(
                "test-provider",
                identity_client=identity_client,
            ),
            propagate_user_token_as_tip=True,
        )
        service_credential = AuthCredential(
            auth_type=AuthCredentialTypes.API_KEY,
            api_key="Bearer mcp-service-key",
        )

        await tool._run_async_impl(
            args={},
            tool_context=_mock_tool_context(inbound_credential=None),
            credential=service_credential,
        )

        identity_client.get_workload_access_token.assert_not_called()
        mcp_session_manager.create_session.assert_called_once_with(
            headers={"Authorization": "Bearer mcp-service-key"}
        )


class _FakeCredentialService:
    def __init__(self, credential):
        self.credentials = {"inbound_auth": credential} if credential else {}
        self.auth_config = None

    async def load_credential(self, *, auth_config, callback_context):
        self.auth_config = auth_config
        return self.credentials.get(auth_config.credential_key)


def _mock_tool_context(*, inbound_credential):
    tool_context = Mock()
    tool_context.agent_name = "mcp_authz_agent"
    tool_context._invocation_context = Mock()
    tool_context._invocation_context.app_name = "test_app"
    tool_context._invocation_context.user_id = "user-123"
    tool_context._invocation_context.credential_service = _FakeCredentialService(
        inbound_credential
    )
    tool_context._invocation_context.session = Mock()
    tool_context._invocation_context.session.state = {}
    return tool_context
