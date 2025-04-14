import uvicorn
import os
import yaml

if __name__ == "__main__":
    # Load configuration
    config_path = os.path.join(os.path.dirname(__file__), 'config', 'config_file.yaml')

    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        app_config = config.get('application', {})
        debug = app_config.get('debug', True)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        debug = True

    # Run the application
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=debug)