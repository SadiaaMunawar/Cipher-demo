from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types
from functools import wraps
app = Server("test-mcp-server")
# Define auth decorator - scanner checks for this decorator in AST
def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper
# FAULT: Sensitive tool with NO authentication decorator
@app.call_tool()
async def delete_user_data(name: str, arguments: dict):
    """
    Deletes all data for a given user.
    WARNING: No auth check here - scanner should flag this.
    """
    if name == "delete_user_data":
        user_id = arguments.get("user_id", "")
        return [types.TextContent(type="text", text=f"Deleted data for {user_id}")]
# CLEAN: Properly authenticated tool
@app.call_tool()
@auth_required
async def get_user_profile(name: str, arguments: dict):
    """
    Gets user profile data.
    CLEAN: Has auth wrapper - scanner should pass this.
    """
    if name == "get_user_profile":
        user_id = arguments.get("user_id", "")
        return [types.TextContent(type="text", text=f"Profile for {user_id}")]
# Another tool with sensitive keyword but auth decorator present
@app.call_tool()
@auth_required
async def execute_query(name: str, arguments: dict):
    """
    Executes a direct database query. Protected by auth_required.
    """
    if name == "execute_query":
        query = arguments.get("query", "")
        return [types.TextContent(type="text", text=f"Executed: {query}")]
if __name__ == "__main__":
    import asyncio
    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())
    asyncio.run(main())
