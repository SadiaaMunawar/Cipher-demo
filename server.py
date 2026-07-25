from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types
from functools import wraps

app = Server("test-mcp-server")

# AUTHENTICATION DECORATOR


def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper



# VULNERABLE: Missing Authentication
# Scanner SHOULD flag this


@app.call_tool()
async def delete_user_data(name: str, arguments: dict):
    """
    Deletes all data for a given user.

    INTENTIONALLY VULNERABLE:
    No @auth_required decorator.
    """

    if name == "delete_user_data":
        user_id = arguments.get("user_id", "")

        return [
            types.TextContent(
                type="text",
                text=f"Deleted data for {user_id}"
            )
        ]

# VULNERABLE: Missing Authentication
# Scanner SHOULD flag this


@app.call_tool()
async def update_user_permissions(name: str, arguments: dict):
    """
    Updates permissions or roles for a user.

    INTENTIONALLY VULNERABLE:
    Sensitive operation without authentication.
    """

    if name == "update_user_permissions":
        user_id = arguments.get("user_id", "")
        role = arguments.get("role", "")

        return [
            types.TextContent(
                type="text",
                text=f"Updated {user_id} role to {role}"
            )
        ]


# VULNERABLE: Sensitive Command Operation
# Scanner SHOULD flag this if its policy recognizes
# command/admin/shell related sensitive operations.


@app.call_tool()
async def execute_admin_command(name: str, arguments: dict):
    """
    Executes an administrative command.

    INTENTIONALLY VULNERABLE:
    No authentication decorator.
    """

    if name == "execute_admin_command":
        command = arguments.get("command", "")

        return [
            types.TextContent(
                type="text",
                text=f"Executed administrative command: {command}"
            )
        ]


# CLEAN: Properly Authenticated
# Scanner SHOULD NOT flag this


@app.call_tool()
@auth_required
async def get_user_profile(name: str, arguments: dict):
    """
    Gets user profile data.

    CLEAN:
    Protected with @auth_required.
    """

    if name == "get_user_profile":
        user_id = arguments.get("user_id", "")

        return [
            types.TextContent(
                type="text",
                text=f"Profile for {user_id}"
            )
        ]



# CLEAN: Sensitive keyword but authenticated
# Scanner SHOULD NOT flag this
#

@app.call_tool()
@auth_required
async def execute_query(name: str, arguments: dict):
    """
    Executes a database query.

    CLEAN:
    Protected with @auth_required.
    """

    if name == "execute_query":
        query = arguments.get("query", "")

        return [
            types.TextContent(
                type="text",
                text=f"Executed: {query}"
            )
        ]



@app.call_tool()
@auth_required
async def get_audit_log(name: str, arguments: dict):
    """
    Retrieves audit information.

    CLEAN:
    Protected with @auth_required.
    """

    if name == "get_audit_log":
        user_id = arguments.get("user_id", "")

        return [
            types.TextContent(
                type="text",
                text=f"Audit log for {user_id}"
            )
        ]



@app.call_tool()
async def get_server_status(name: str, arguments: dict):
    """
    Returns server status.

    This is a normal non-sensitive operation and does not
    require authentication.
    """

    if name == "get_server_status":
        return [
            types.TextContent(
                type="text",
                text="Server is running normally."
            )
        ]
# MCP SERVER STARTUP


if __name__ == "__main__":
    import asyncio

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )

    asyncio.run(main())