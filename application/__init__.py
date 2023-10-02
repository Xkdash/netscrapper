from flask import Flask

def create_app():
    app = Flask(__name__)
    with app.app_context():
        app.secret_key="abc"
        from application.dashboard import dash_bp

        # Register Blueprints
        app.register_blueprint(dash_bp)
    return app
