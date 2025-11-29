"""
Vercel serverless function entry point for Flask app
Vercel looks for 'app' variable in api/index.py
"""
import os
import sys

# Set Vercel environment variables BEFORE any imports
os.environ["DISABLE_MONITORING"] = "1"
os.environ["VERCEL"] = "1"

# Add current directory and parent to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

# Add paths to sys.path
for path in [parent_dir, current_dir, "/var/task"]:
    if path not in sys.path:
        sys.path.insert(0, path)

# Now import Flask app
try:
    # Standard import
    from app import create_app
    app = create_app()
except Exception as e:
    # If import fails, try alternative approach
    import traceback
    error_msg = f"Import error: {str(e)}\n{traceback.format_exc()}"
    print(error_msg, file=sys.stderr)
    
    # Try using importlib
    try:
        import importlib.util
        app_init_path = os.path.join(parent_dir, "app", "__init__.py")
        if os.path.exists(app_init_path):
            spec = importlib.util.spec_from_file_location("app", app_init_path)
            if spec and spec.loader:
                app_module = importlib.util.module_from_spec(spec)
                sys.modules["app"] = app_module
                spec.loader.exec_module(app_module)
                app = app_module.create_app()
            else:
                raise Exception("Could not create module spec")
        else:
            raise Exception(f"app/__init__.py not found at {app_init_path}")
    except Exception as e2:
        # Last resort: minimal error app
        print(f"Fallback error: {e2}", file=sys.stderr)
        from flask import Flask
        app = Flask(__name__)
        
        @app.route("/")
        @app.route("/<path:path>")
        def error_handler(path=""):
            return f"""
            <html>
            <head><title>FIMonacci - Initialization Error</title></head>
            <body style="font-family: Arial, sans-serif; padding: 50px; text-align: center;">
                <h1>Application Initialization Error</h1>
                <p>Please check the Vercel logs for details.</p>
                <pre style="text-align: left; background: #f5f5f5; padding: 20px; border-radius: 5px; max-width: 800px; margin: 20px auto;">
Error: {str(e)}
Secondary Error: {str(e2)}
                </pre>
            </body>
            </html>
            """, 500
