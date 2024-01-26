import glob
import os
import oyaml as yaml
from pathlib import Path

def process_atomic_yaml(input_file):
    with open(input_file, 'r', encoding='utf-8') as file:
        atomic_yaml = yaml.safe_load(file)

    attack_technique = atomic_yaml.get('attack_technique', '')
    atomic_tests = atomic_yaml.get('atomic_tests', [])

    linux_atomic_tests = [test for test in atomic_tests if 'linux' in test.get('supported_platforms', [])]

    return attack_technique, linux_atomic_tests

def update_output_file(output_path, atomics):
    output_file = open(output_path, 'r+', encoding='utf-8')
    existing_data = yaml.safe_load(output_file)
    technique_idx = -1

    if not existing_data or 'atomics' not in existing_data:
        existing_data = {"atomics": []}

    index = {atomic['attack_technique']: (idx, atomic['atomic_tests']) for idx, atomic in enumerate(existing_data['atomics'])}

    for attack_technique, atomic_tests in atomics.items():
        if attack_technique in index:
            technique_idx = index[attack_technique][0]
        else:
            existing_data['atomics'].append({"attack_technique": attack_technique, "atomic_tests": []})
            technique_idx = len(existing_data['atomics']) - 1
            index[attack_technique] = (technique_idx, [])
        existing_tests_guids = [t['auto_generated_guid'] for t in index[attack_technique][1]]
        new_tests = [t for t in atomic_tests if t['auto_generated_guid'] not in existing_tests_guids]


        for test in new_tests:
            test_uuid = test['auto_generated_guid']
                    
            reduced_test = {
                "name": test["name"],
                "auto_generated_guid": test["auto_generated_guid"],
            } 

            existing_data['atomics'][technique_idx]["atomic_tests"].append(reduced_test)

    yaml.dump(existing_data, output_file, default_flow_style=False)
    output_file.close()

def gather_atomics(files):
    atomics = {}
    for file in files:
        attack_technique, linux_atomic_tests = process_atomic_yaml(file)

        if linux_atomic_tests:
            if attack_technique not in atomics:
                atomics[attack_technique] = []
            atomics[attack_technique].extend(linux_atomic_tests)
    return atomics

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Process Atomic Red Team YAML files for Linux platform.')
    parser.add_argument('input_directory', help='Directory containing atomic subdirectories in the format <T..>/<T....yaml>')
    parser.add_argument('output_file', help='Output file in the specified format')
    args = parser.parse_args()


    files = glob.glob('**/T*.yaml', recursive=True)

    atomics = gather_atomics(files)

    Path(args.output_file).touch()
    update_output_file(args.output_file, atomics)

