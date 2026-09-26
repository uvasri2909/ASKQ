# backend/tools

## `askq_isolate_base_dir.pth`: import-path isolation for the venv

On Windows, the root folder of the global Python installation
(e.g. `...\Programs\Python\Python313`) is on the import path of **every** virtual
environment, *before* `site-packages`. Any personal `.py` file saved there, such as a
`py.py` or `main.py`, silently shadows real modules. For example, a `py.py` there
breaks pytest, which imports a module named `py`.

Python executes `import` lines in `.pth` files found in `site-packages` at startup.
This one-line file removes **only that exact folder** from `sys.path` inside the ASKQ
venv. The standard library (`Lib`, `DLLs`, `python313.zip`) is unaffected, and nothing
outside the project is modified.

`setup.ps1` copies it into `.venv\Lib\site-packages\`. The test
`tests/test_environment.py` fails if the isolation is missing.
