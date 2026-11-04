# pa-permission-conditional-access-simulator

Simulates the impact of implementing conditional access policies on user access based on various contextual factors (time, location, device health, etc.). Provides a preview of how changes would impact end users. Focused on tools for analyzing and assessing file system permissions.

This tool uses only the Python standard library. No third party packages are required and there is no requirements file.

Missing, unparseable, or structurally empty input files exit 1 with an input error line, and no access verdict is printed. An unknown user exits 1 with a user not found line. The denied verdict is printed only for a user who was evaluated. The evaluation time is read from the context file (the time field inside the context object) when present, and that use is logged; when the context carries no time, the wall clock is used and that use is logged. A matching policy whose access value is block or deny takes precedence over grant policies, stops evaluation with a denial, and is logged by name. Policy time strings are validated at load, and a bad value exits 1 naming the policy and the value.

## Install

```
git clone https://github.com/ShadowGuard-AI/pa-permission-conditional-access-simulator.git
cd pa-permission-conditional-access-simulator
```

## Usage

```
python3 main.py USER_ID [options]
```

## Parameters

- `USER_ID`: Required positional. The ID of the user to simulate access for.
- `-p, --policy_file`: Path to the policy JSON file, default `policies.json`.
- `-u, --user_file`: Path to the user JSON file, default `users.json`.
- `-c, --context_file`: Path to the context JSON file, default `context.json`.

## Verified in this wave

`python3 main.py --help` exits 0. A sample with one enabled grant policy for alice, a users file with alice and bob, and a context file with time 10:00 printed "Access granted to user 'alice'." and exit 0. An unknown user exits 1 with "User not found: nobody". No positional argument exits 2 with the required `user_id` error.

## License

See LICENSE.
