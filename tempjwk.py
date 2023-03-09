#!/usr/bin/env python3
import subprocess
import time
import select
import pathlib
import sys
import tempfile
import argparse


def check_provisioner(provisioner_name: str) -> bool:
    provisioner_exists_command = ["step-cli", "ca", "provisioner", "list"]
    provisioner_exists_process = subprocess.run(
        provisioner_exists_command,
        capture_output=True,
        text=True,
        check=True)

    if provisioner_name in provisioner_exists_process.stdout:
        return True

    return False


def delete_provisioner(provisioner_name: str, admin_provisioner: str, admin_subject: str):
    delete_command = ["step-cli", "ca", "provisioner", "remove",
                      provisioner_name,
                      "--admin-provisioner", admin_provisioner,
                      "--admin-subject", admin_subject]

    try:
        delete_process = subprocess.run(delete_command, check=True)
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Error: Failed to delete provisioner: {e}")


def add_provisioner(provisioner_name: str, admin_provisioner: str, admin_subject: str, private_key_path: str, public_key_path: str):
    # Decrypt the private key using gpg and write it to a temporary file
    with tempfile.NamedTemporaryFile() as temp_file:
        gpg_command = ["gpg", "--decrypt", str(private_key_path)]
        gpg_process = subprocess.run(gpg_command, stdout=temp_file)

        if gpg_process.returncode != 0:
            raise ValueError("Failed to decrypt private key")

        try:
            # Add the JWK provisioner using the step CLI
            step_command = [
                "step-cli", "ca", "provisioner", "add",
                "--type", "jwk",
                "--public-key", str(public_key_path),
                "--private-key", temp_file.name,
                provisioner_name,
                "--admin-provisioner", admin_provisioner,
                "--admin-subject", admin_subject,
            ]
            step_process = subprocess.run(step_command, check=True)
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Error: Failed to add provisioner: {e}")


def decrypt_file(input_file: pathlib.Path, output_file: pathlib.Path = None) -> pathlib.Path:
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        gpg_command = ["gpg", "--decrypt", str(input_file)]

        try:
            gpg_process = subprocess.run(
                gpg_command, stdout=temp_file, check=True)
        except subprocess.CalledProcessError as e:
            pathlib.Path(temp_file.name).unlink()
            raise ValueError(f"Error: Failed decrypting file: {e}")

        return pathlib.Path(temp_file.name)


def main():
    # Get the script's directory
    script_dir = pathlib.Path(__file__).parent

    parser = argparse.ArgumentParser(
        description="Add and delete a JWK provisioner using the Step CLI.")
    parser.add_argument("--admin-provisioner", dest="admin_provisioner", default="KumiDC",
                        help="The name of the admin provisioner to use. Default is 'KumiDC'.")
    parser.add_argument("--admin-subject", dest="admin_subject", default="admin",
                        help="The email address of the admin subject to use. Default is 'admin'.")
    parser.add_argument("--provisioner-name", dest="provisioner_name", default="tempjwk",
                        help="The name of the JWK provisioner to add/delete. Default is 'tempjwk'.")
    parser.add_argument("--public-key", dest="public_key_path", default="key.pub",
                        help="The path to the public key file for the provisioner. Default is 'key.pub'.")
    parser.add_argument("--private-key", dest="private_key_path", default="key.priv.gpg",
                        help="The path to the GPG encrypted private key file for the provisioner. Default is 'key.priv.gpg'.")
    parser.add_argument("--timeout", dest="timeout", type=int, default=300,
                        help="The number of seconds to wait for the user to delete the provisioner. Default is 300 seconds.")

    args = parser.parse_args()

    # Construct the full default paths to the key files
    public_key_path = script_dir / args.public_key_path
    private_key_path = script_dir / args.private_key_path

    # Check that the public key file exists
    if not public_key_path.exists():
        print("Error: public key file does not exist")
        exit(1)

    try:
        provisioner_exists = check_provisioner(args.provisioner_name)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to check if provisioner exists: {e}")
        exit(1)

    if provisioner_exists:
        print(
            f"Provisioner {args.provisioner_name} already exists. Deleting existing provisioner...")
        try:
            delete_provisioner(args.provisioner_name,
                               args.admin_provisioner,
                               args.admin_subject)

        except subprocess.CalledProcessError as e:
            print(
                f"Error: Failed to delete existing provisioner {args.provisioner_name}: {e}")
            exit(1)

        print(f"Existing provisioner {args.provisioner_name} deleted.")

    try:
        add_provisioner(args.provisioner_name,
                        args.admin_provisioner,
                        args.admin_subject,
                        args.private_key_path,
                        args.public_key_path)

    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to add provisioner {args.provisioner_name}: {e}")
        exit(1)

    print(f"Provisioner {args.provisioner_name} added.")
    print(f"Press any key to delete it (up to {args.timeout} seconds)")

    # Wait for the user to press any key (up to TIMEOUT seconds)
    start_time = time.time()
    while True:
        if time.time() - start_time > args.timeout:
            break
        if select.select([sys.stdin,], [], [], 0.5)[0]:
            break

    # Delete the provisioner
    try:
        delete_provisioner(args.provisioner_name,
                           args.admin_provisioner,
                           args.admin_subject)
    except subprocess.CalledProcessError as e:
        print(
            f"Error: Failed to delete provisioner {args.provisioner_name}: {e}")
        exit(1)

    print(f"Provisioner {args.provisioner_name} deleted.")


if __name__ == "__main__":
    main()
