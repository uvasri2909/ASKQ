"""Language-model integration.

The rest of the backend depends only on the SqlGenerator protocol
(sql_generator.py); claude.py is the one module that imports the Anthropic
SDK. Everything a generator returns is untrusted input to the query pipeline.
"""
