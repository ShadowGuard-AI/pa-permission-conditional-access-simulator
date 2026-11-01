import argparse
import logging
import json
import os
import sys
from datetime import datetime
from typing import Dict, Any, List

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for default values
DEFAULT_POLICY_FILE = "policies.json"
DEFAULT_USER_FILE = "users.json"
DEFAULT_CONTEXT_FILE = "context.json"

class PolicySimulator:
    """
    Simulates the impact of conditional access policies on user access.
    """

    def __init__(self, policy_file: str, user_file: str, context_file: str):
        """
        Initializes the PolicySimulator with policy, user, and context data.

        Args:
            policy_file (str): Path to the JSON file containing policies.
            user_file (str): Path to the JSON file containing user data.
            context_file (str): Path to the JSON file containing context data.
        """
        self.policy_file = policy_file
        self.user_file = user_file
        self.context_file = context_file
        self.policies = self._load_data(policy_file)
        self.users = self._load_data(user_file)
        self.context = self._load_data(context_file)
        for label, data in (("policy", self.policies), ("user", self.users), ("context", self.context)):
            if not isinstance(data, dict) or not data:
                raise ValueError(f"Input error: {label} data is empty or invalid.")
        self._validate_policy_times()
        self._validate_context_time()

    def _parse_time(self, value):
        for fmt in ("%H:%M", "%H:%M:%S"):
            try:
                return datetime.strptime(str(value), fmt).time()
            except ValueError:
                continue
        return None

    def _validate_policy_times(self):
        for policy in self.policies.get("policies", []) or []:
            time_restrictions = (policy.get("conditions", {}) or {}).get("time", {}) or {}
            for key in ("start_time", "end_time"):
                if key in time_restrictions and time_restrictions.get(key) is not None:
                    value = time_restrictions.get(key)
                    if self._parse_time(value) is None:
                        raise ValueError(f"Input error: Policy '{policy.get('name')}' has invalid time value '{value}' for {key}.")

    def _validate_context_time(self):
        context_data = self.context.get("context", {}) if isinstance(self.context.get("context", {}), dict) else {}
        value = context_data.get("time", self.context.get("time"))
        if value is not None and self._parse_time(value) is None:
            raise ValueError(f"Input error: Context has invalid time value '{value}'.")


    def _load_data(self, file_path: str) -> Dict[str, Any]:
        """
        Loads data from a JSON file.

        Args:
            file_path (str): The path to the JSON file.

        Returns:
            Dict[str, Any]: The loaded data as a dictionary.  Returns an empty dictionary if an error occurs.
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            logging.info(f"Successfully loaded data from {file_path}")
            return data
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            raise ValueError(f"Input error: File not found: {file_path}")
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON format in {file_path}")
            raise ValueError(f"Input error: Invalid JSON format in {file_path}")
        except Exception as e:
            logging.error(f"Error loading data from {file_path}: {e}")
            raise ValueError(f"Input error: Error loading data from {file_path}: {e}")

    def simulate_access(self, user_id: str) -> bool:
        """
        Simulates access for a given user based on defined policies and context.

        Args:
            user_id (str): The ID of the user to simulate access for.

        Returns:
            bool: True if access is granted, False otherwise.
        """

        if not self.policies or not self.users or not self.context:
             raise ValueError("Input error: Data is not loaded. Check that the policy, user, and context files are valid and accessible.")

        user_data = next((user for user in self.users.get("users", []) if user["id"] == user_id), None)

        if not user_data:
            logging.warning(f"User with ID '{user_id}' not found.")
            raise LookupError(f"User not found: '{user_id}'")

        # Contextual information. The evaluation time comes from the
        # context file when it carries one; otherwise the wall clock is used.
        context_data = self.context.get("context", {})
        if not isinstance(context_data, dict):
            context_data = {}
        context_time_value = context_data.get("time", self.context.get("time"))
        if context_time_value is not None:
            current_time = self._parse_time(context_time_value)
            logging.info(f"Using evaluation time from context file: {context_time_value}")
            print(f"Using evaluation time from context file: {context_time_value}")
        else:
            current_time = datetime.now().time()
            logging.info(f"Using current wall clock time: {current_time}")
            print(f"Using current wall clock time: {current_time}")

        matching = []
        for policy in self.policies.get("policies", []):
            if policy.get("status") != "enabled":
                continue
            if user_id not in policy.get("users", []):
                continue
            conditions = policy.get("conditions", {}) or {}
            time_condition_met = True
            time_restrictions = conditions.get("time", {}) or {}
            if time_restrictions:
                start_time = self._parse_time(time_restrictions.get("start_time", "00:00"))
                end_time = self._parse_time(time_restrictions.get("end_time", "23:59"))
                if start_time is None or end_time is None:
                    raise ValueError(f"Input error: Policy '{policy.get('name')}' has an invalid time value.")
                if not (start_time <= current_time <= end_time):
                    time_condition_met = False
            location_condition_met = True
            allowed_locations = conditions.get("location", [])
            if allowed_locations:
                user_location = context_data.get("location")
                if user_location not in allowed_locations:
                    location_condition_met = False
            device_health_met = True
            required_device_health = conditions.get("device_health", "")
            if required_device_health:
                current_device_health = context_data.get("device_health")
                if current_device_health != required_device_health:
                    device_health_met = False
            if time_condition_met and location_condition_met and device_health_met:
                matching.append(policy)
            else:
                logging.info(f"Policy '{policy.get('name')}' conditions not met for user '{user_id}'.")

        # A matching block policy takes precedence and stops evaluation.
        for policy in matching:
            access_value = str((policy.get("grant_controls", {}) or {}).get("access", "")).strip().lower()
            if access_value in ("block", "deny"):
                logging.info(f"Policy '{policy.get('name')}' blocked access to user '{user_id}'.")
                print(f"Policy '{policy.get('name')}' blocked access to user '{user_id}'.")
                return False

        access_granted = False
        for policy in matching:
            grant_controls = policy.get("grant_controls", {}) or {}
            if str(grant_controls.get("access", "")).strip().lower() == "grant":
                access_granted = True
                logging.info(f"Policy '{policy.get('name')}' granted access to user '{user_id}'.")
                break
            else:
                logging.info(f"Policy '{policy.get('name')}' applied but does not grant access to user '{user_id}'.")

        if not access_granted:
            logging.info(f"Access denied to user '{user_id}' based on configured policies.")
        return access_granted


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Simulate conditional access policies for users.")
    parser.add_argument("-p", "--policy_file", type=str, default=DEFAULT_POLICY_FILE,
                        help="Path to the policy JSON file. Default: policies.json")
    parser.add_argument("-u", "--user_file", type=str, default=DEFAULT_USER_FILE,
                        help="Path to the user JSON file. Default: users.json")
    parser.add_argument("-c", "--context_file", type=str, default=DEFAULT_CONTEXT_FILE,
                        help="Path to the context JSON file. Default: context.json")
    parser.add_argument("user_id", type=str,
                        help="The ID of the user to simulate access for.")

    return parser


def main() -> None:
    """
    Main function to parse arguments and run the policy simulation.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input Validation
    for label, path in (("Policy", args.policy_file), ("User", args.user_file), ("Context", args.context_file)):
        if not os.path.exists(path):
            print(f"Input error: {label} file not found: {path}")
            logging.error(f"{label} file not found: {path}")
            sys.exit(1)

    try:
        simulator = PolicySimulator(args.policy_file, args.user_file, args.context_file)
        access_granted = simulator.simulate_access(args.user_id)
    except LookupError as e:
        print(f"User not found: {args.user_id}")
        logging.error(str(e))
        sys.exit(1)
    except ValueError as e:
        message = str(e)
        if message.startswith("Input error:"):
            print(message)
        else:
            print(f"Input error: {message}")
        logging.error(message)
        sys.exit(1)

    if access_granted:
        print(f"Access granted to user '{args.user_id}'.")
    else:
        print(f"Access denied to user '{args.user_id}'.")


if __name__ == "__main__":
    """
    Example Usage:
    
    1.  Create three JSON files: policies.json, users.json, and context.json.
        See the example content below.
    2.  Run the script with a user ID:
        python main.py <user_id>
    
    Example policies.json:
    {
        "policies": [
            {
                "name": "Policy 1",
                "status": "enabled",
                "users": ["user1"],
                "conditions": {
                    "time": {
                        "start_time": "08:00",
                        "end_time": "18:00"
                    },
                    "location": ["USA"],
                    "device_health": "compliant"
                },
                "grant_controls": {
                    "access": "grant"
                }
            },
            {
                "name": "Policy 2",
                "status": "enabled",
                "users": ["user2"],
                "conditions": {
                    "location": ["Canada"]
                },
                "grant_controls": {
                    "access": "grant"
                }
            }
        ]
    }
    
    Example users.json:
    {
        "users": [
            {
                "id": "user1",
                "name": "John Doe"
            },
            {
                "id": "user2",
                "name": "Jane Smith"
            }
        ]
    }
    
    Example context.json:
    {
        "context": {
            "location": "USA",
            "device_health": "compliant"
        }
    }
    """
    main()