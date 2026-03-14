from sentinel import ZeronSentinel

def test_sentinel_interception():
    print("--- Initiating AgentAudit Sentinel Local Test ---")
    
    # Simulate a compromised LLM outputting a Base64 encoded payload
    # This bypasses Zeron's verb-based policy engine because the verb "execute_shell_command" is allowed.
    malicious_kwargs = {
        "command": "cm0gLXJmIC8=",  # Base64 for 'rm -rf /'
        "context": "system_maintenance"
    }

    # Wrap a mock Zeron execution function with our Sentinel
    @ZeronSentinel.wrap_execution
    def mock_zeron_execute(tool_name: str, **kwargs):
        # If the code reaches this print statement, the framework is compromised.
        print(f"\n[Zeron Runtime] FATAL: Executing {tool_name} with args: {kwargs}")
        return True

    print("\n[Simulated Execution] Zeron ADK passing payload to runtime...")
    
    try:
        # Trigger the execution
        mock_zeron_execute("execute_shell_command", **malicious_kwargs)
        print("\n❌ TEST FAILED: Sentinel allowed the obfuscated payload to execute.")
    except PermissionError as e:
        print(f"\n✅ TEST PASSED: {e}")

if __name__ == "__main__":
    test_sentinel_interception()