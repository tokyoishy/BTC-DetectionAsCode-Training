from pathlib import Path
from detection_deployer import DetectionDeployer
from test_detections import load_environment_variables, find_yaml_files, load_sigma_detection


def main():
    print("Loading environment variables...")
    env_vars = load_environment_variables()
    deployer = DetectionDeployer(
        host=env_vars['host'],
        username=env_vars['username'],
        password=env_vars['password'],
        lab_host="lab8"
    )

    yaml_files = find_yaml_files("detections")

    for yaml_file in yaml_files:
        file_name = Path(yaml_file).name
        file_name = file_name.split('.')[0]
        print(f"\nLoading detection from: {file_name}")

        detection_data = load_sigma_detection(yaml_file)
        if detection_data is None:
            print(f"❌ Skipping {file_name} due to loading errors")
            failed_tests += 1
            continue

        deployer.sigma_to_splunk_conversion(detection_data)
        deployer.deploy_splunk_detection(detection_data, file_name)
        print(f"✅ Successfully deployed: {file_name}")

if __name__ == "__main__":
    main()