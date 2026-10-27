"""Language-model integration.

The rest of the backend depends only on the SqlGenerator protocol
(sql_generator.py). Two providers implement it, chosen by LLM_PROVIDER:
claude.py (the one module that imports the Anthropic SDK) and ollama.py (a
local Ollama server). Both send the same prompt (prompt.py) and return output
validated against the same strict schema. Everything a generator returns is
untrusted input to the query pipeline, whichever provider produced it.
"""
