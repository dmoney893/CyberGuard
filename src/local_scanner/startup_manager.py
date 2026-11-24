import os
import json
import platform
import subprocess
import time
from pathlib import Path

if platform.system() == "Windows":
    import winreg


def get_installed_app_names():
    script = """
    Get-StartApps |
    Select-Object Name, AppID |
    ConvertTo-Json -Compress
    """

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        if result.returncode != 0 or not result.stdout.strip():
            return {}

        data = json.loads(result.stdout)

        if isinstance(data, dict):
            data = [data]

        names = {}

        for item in data:
            app_id = item.get("AppID", "")
            name = item.get("Name", "")

            if app_id and name:
                names[app_id.lower()] = name

        return names

    except Exception:
        return {}


def get_executable_path(command):
    command = os.path.expandvars(command).strip()

    if command.startswith('"'):
        parts = command.split('"')

        if len(parts) > 1:
            return parts[1]

    position = command.lower().find(".exe")

    if position != -1:
        return command[:position + 4].strip()

    return None


def get_executable_names(paths):
    if not paths:
        return {}

    payload = json.dumps(list(set(paths)))

    script = """
    $paths = ConvertFrom-Json $env:CYBERGUARD_EXECUTABLE_PATHS

    $results = @(
        foreach ($path in $paths) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                try {
                    $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)

                    $name = $info.FileDescription

                    if ([string]::IsNullOrWhiteSpace($name)) {
                        $name = $info.ProductName
                    }

                    if (-not [string]::IsNullOrWhiteSpace($name)) {
                        [PSCustomObject]@{
                            Path = $path
                            Name = $name
                        }
                    }
                }
                catch {}
            }
        }
    )

    ConvertTo-Json -InputObject $results -Compress
    """

    try:
        environment = os.environ.copy()
        environment["CYBERGUARD_EXECUTABLE_PATHS"] = payload

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script
            ],
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        if result.returncode != 0 or not result.stdout.strip():
            return {}

        data = json.loads(result.stdout)

        if isinstance(data, dict):
            data = [data]

        return {
            item["Path"].lower(): item["Name"]
            for item in data
            if item.get("Path") and item.get("Name")
        }

    except Exception:
        return {}

def is_startup_manageable(application):
    if application.get("source") != "Registry":
        return False

    if application.get("scope") != "Current User":
        return False

    if application.get("category") != "Run":
        return False

    if application.get("enabled") is None:
        return False
    try:
        approved_path = (
            r"Software\Microsoft\Windows\CurrentVersion"
            r"\Explorer\StartupApproved\Run"
        )

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            approved_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            value, value_type = winreg.QueryValueEx(
                key,
                application["original_name"]
            )

            if value_type != winreg.REG_BINARY:
                return False

            if not isinstance(value, bytes) or len(value) != 12:
                return False

            if int.from_bytes(value[:4], "little") not in (2, 3):
                return False

    except OSError:
        return False

    executable = application.get("executable")

    if not executable:
        return False

    try:
        executable_path = Path(executable).resolve()

        if not executable_path.is_file():
            return False

        allowed_directories = [
            os.environ.get("LOCALAPPDATA"),
            os.environ.get("APPDATA")
        ]

        return any(
            executable_path.is_relative_to(Path(directory).resolve())
            for directory in allowed_directories
            if directory
        )

    except (OSError, ValueError):
        return False
def get_installed_applications():
    if platform.system() != "Windows":
        return []

    applications = []
    uninstall_path = (
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    sources = [
        (winreg.HKEY_CURRENT_USER, winreg.KEY_READ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            winreg.KEY_READ | winreg.KEY_WOW64_32KEY
        )
    ]

    def read_value(key, name, default=""):
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return default

    for root, access in sources:
        try:
            with winreg.OpenKey(
                root, uninstall_path, 0, access
            ) as registry:

                count = winreg.QueryInfoKey(registry)[0]

                for index in range(count):
                    try:
                        subkey = winreg.EnumKey(registry, index)

                        with winreg.OpenKey(
                            registry, subkey, 0, access
                        ) as key:

                            name = read_value(key, "DisplayName")

                            if not name:
                                continue

                            if read_value(key, "SystemComponent", 0) == 1:
                                continue

                            applications.append({
                                "name": name,
                                "publisher": read_value(key, "Publisher"),
                                "location": read_value(key, "InstallLocation"),
                                "display_icon": read_value(key, "DisplayIcon"),
                                "uninstall": read_value(key, "UninstallString"),
                                "scope": (
                                    "Current User"
                                    if root == winreg.HKEY_CURRENT_USER
                                    else "All Users"
                                )
                            })

                    except OSError:
                        continue

        except OSError:
            continue

    return applications

def match_installed_application(executable, installed_apps):
    if not executable:
        return None

    executable = os.path.normcase(
        os.path.abspath(os.path.expandvars(executable))
    )

    matches = []

    for app in installed_apps:
        location = app.get("location")

        if location and isinstance(location, str):
            location = os.path.normcase(
                os.path.abspath(
                    os.path.expandvars(location.strip('" '))
                )
            )

            try:
                if (
                    os.path.commonpath([executable, location]) == location
                    and location != os.path.splitdrive(location)[0] + "\\"
                ):
                    matches.append((len(location), app))
            except ValueError:
                pass

        icon = app.get("display_icon")

        if icon and isinstance(icon, str):
            icon_path = get_executable_path(icon)

            if icon_path:
                icon_path = os.path.normcase(
                    os.path.abspath(os.path.expandvars(icon_path))
                )

                if executable == icon_path:
                    matches.append((len(icon_path), app))

    if not matches:
        return None

    matches.sort(key=lambda item: item[0], reverse=True)

    return matches[0][1]

def get_startup_applications():
    if platform.system() != "Windows":
        return {
            "supported": False,
            "applications": [],
            "summary": {
                "total": 0,
                "enabled": 0,
                "disabled": 0,
                "unknown": 0
            }
        }

    applications = []

    run_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

    approved_path = (
        r"Software\Microsoft\Windows\CurrentVersion"
        r"\Explorer\StartupApproved"
    )

    def get_startup_status(root, category, name):
        try:
            with winreg.OpenKey(
                root,
                f"{approved_path}\\{category}",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as key:
                value, value_type = winreg.QueryValueEx(
                    key,
                    name
                )

                if value_type != winreg.REG_BINARY:
                    return None

                if not isinstance(value, bytes) or len(value) < 4:
                    return None

                state = int.from_bytes(value[:4], "little")

                if state in (2, 6):
                    return True

                if state in (3, 7):
                    return False

                return None

        except FileNotFoundError:
            return True

        except OSError:
            return None

    registry_sources = [
        (
            winreg.HKEY_CURRENT_USER,
            "Current User",
            winreg.KEY_READ,
            "Run"
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            "All Users",
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            "Run"
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            "All Users",
            winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
            "Run32"
        )
    ]

    for root, scope, access, category in registry_sources:
        try:
            with winreg.OpenKey(
                root,
                run_path,
                0,
                access
            ) as key:

                count = winreg.QueryInfoKey(key)[1]

                for index in range(count):
                    name, command, value_type = winreg.EnumValue(
                        key,
                        index
                    )

                    if value_type not in (
                        winreg.REG_SZ,
                        winreg.REG_EXPAND_SZ
                    ):
                        continue

                    applications.append({
                        "id": f"registry:{scope}:{category}:{name}",
                        "name": name,
                        "original_name": name,
                        "command": command,
                        "executable": get_executable_path(command),
                        "source": "Registry",
                        "scope": scope,
                        "category": category,
                        "enabled": get_startup_status(
                            root,
                            category,
                            name
                        ),
                        "manageable": False
                    })

        except OSError:
            continue

    startup_folders = [
        (
            os.environ.get("APPDATA"),
            "Current User",
            winreg.HKEY_CURRENT_USER
        ),
        (
            os.environ.get("PROGRAMDATA"),
            "All Users",
            winreg.HKEY_LOCAL_MACHINE
        )
    ]

    for base, scope, root in startup_folders:
        if not base:
            continue

        folder = (
            Path(base)
            / "Microsoft"
            / "Windows"
            / "Start Menu"
            / "Programs"
            / "Startup"
        )

        if not folder.exists():
            continue

        try:
            for item in folder.iterdir():
                if not item.is_file():
                    continue

                if item.name.lower() == "desktop.ini":
                    continue

                applications.append({
                    "id": f"folder:{scope}:{item.name}",
                    "name": item.stem,
                    "original_name": item.name,
                    "command": str(item),
                    "executable": (
                        str(item)
                        if item.suffix.lower() == ".exe"
                        else None
                    ),
                    "source": "Startup Folder",
                    "scope": scope,
                    "category": "StartupFolder",
                    "enabled": get_startup_status(
                        root,
                        "StartupFolder",
                        item.name
                    ),
                    "manageable": False
                })

        except OSError:
            continue

    installed_names = get_installed_app_names()

    packaged_path = (
        r"Software\Classes\Local Settings\Software"
        r"\Microsoft\Windows\CurrentVersion"
        r"\AppModel\SystemAppData"
    )

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            packaged_path
        ) as packages:

            package_count = winreg.QueryInfoKey(packages)[0]

            for index in range(package_count):
                package = winreg.EnumKey(packages, index)

                try:
                    with winreg.OpenKey(
                        packages,
                        package
                    ) as package_key:

                        task_count = winreg.QueryInfoKey(
                            package_key
                        )[0]

                        for task_index in range(task_count):
                            task = winreg.EnumKey(
                                package_key,
                                task_index
                            )

                            try:
                                with winreg.OpenKey(
                                    package_key,
                                    task
                                ) as task_key:

                                    state, value_type = winreg.QueryValueEx(
                                        task_key,
                                        "State"
                                    )

                                    if value_type != winreg.REG_DWORD:
                                        continue

                                    matching_names = {
                                        display_name
                                        for app_id, display_name
                                        in installed_names.items()
                                        if app_id.startswith(
                                            package.lower() + "!"
                                        )
                                    }

                                    if len(matching_names) == 1:
                                        name = next(iter(matching_names))
                                    else:
                                        name = package.rsplit("_", 1)[0]

                                    applications.append({
                                        "id": f"packaged:{package}:{task}",
                                        "name": name,
                                        "original_name": task,
                                        "command": package,
                                        "executable": None,
                                        "source": "Packaged Application",
                                        "scope": "Current User",
                                        "category": "StartupTask",
                                        "enabled": None,
                                        "reported_state": state,
                                        "manageable": False
                                    })

                            except OSError:
                                continue

                except OSError:
                    continue

    except OSError:
        pass

    executable_paths = [
        item["executable"]
        for item in applications
        if item.get("executable")
    ]

    executable_names = get_executable_names(executable_paths)

    for item in applications:
        executable = item.get("executable")

        if executable:
            display_name = executable_names.get(
                executable.lower()
            )

            if display_name:
                item["name"] = display_name
        installed_apps = get_installed_applications()
    filtered_applications = []

    for item in applications:
        installed_app = match_installed_application(
            item.get("executable"),
            installed_apps
        )

        if installed_app is None:
            continue

        if installed_app.get("scope") != "Current User":
            continue

        if not is_startup_manageable(item):
            continue

        item["publisher"] = installed_app.get("publisher", "")
        item["installed_name"] = installed_app["name"]
        item["manageable"] = True

        filtered_applications.append(item)

    applications = filtered_applications
    applications = list({
        item["id"]: item
        for item in applications
    }.values())

    applications.sort(
        key=lambda item: item["name"].lower()
    )

    return {
        "supported": True,
        "applications": applications,
        "summary": {
            "total": len(applications),
            "enabled": sum(
                item["enabled"] is True
                for item in applications
            ),
            "disabled": sum(
                item["enabled"] is False
                for item in applications
            ),
            "unknown": sum(
                item["enabled"] is None
                for item in applications
            )
        }
    }

def set_startup_application_state(application_id, enabled):
    if platform.system() != "Windows":
        raise ValueError("Startup management is not supported.")

    if type(enabled) is not bool:
        raise ValueError("Invalid startup state.")

    prefix = "registry:Current User:Run:"

    if not isinstance(application_id, str) or not application_id.startswith(prefix):
        raise PermissionError("This startup application cannot be modified.")

    name = application_id[len(prefix):]

    if not name or "\x00" in name:
        raise ValueError("Invalid startup application.")

    run_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

    approved_path = (
        r"Software\Microsoft\Windows\CurrentVersion"
        r"\Explorer\StartupApproved\Run"
    )

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            run_path,
            0,
            winreg.KEY_READ
        ) as key:
            command, value_type = winreg.QueryValueEx(key, name)

        if value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            raise PermissionError("Invalid startup registration.")

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            approved_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            current_value, current_type = winreg.QueryValueEx(key, name)

    except OSError:
        raise ValueError("Startup application not found.")

    if (
        current_type != winreg.REG_BINARY
        or not isinstance(current_value, bytes)
        or len(current_value) != 12
    ):
        raise PermissionError("Unsupported startup configuration.")

    current_state = int.from_bytes(current_value[:4], "little")

    if current_state not in (2, 3):
        raise PermissionError("Unsupported startup state.")

    executable = get_executable_path(command)

    installed_apps = get_installed_applications()

    installed_app = match_installed_application(
        executable,
        installed_apps
    )

    if installed_app is None:
        raise PermissionError("Installed application could not be verified.")

    if installed_app.get("scope") != "Current User":
        raise PermissionError("This startup application cannot be modified.")

    application = {
        "id": application_id,
        "name": installed_app["name"],
        "original_name": name,
        "command": command,
        "executable": executable,
        "source": "Registry",
        "scope": "Current User",
        "category": "Run",
        "enabled": current_state == 2,
        "manageable": False,
        "publisher": installed_app.get("publisher", ""),
        "installed_name": installed_app["name"]
    }

    if not is_startup_manageable(application):
        raise PermissionError("This startup application cannot be modified.")

    application["manageable"] = True

    if application["enabled"] == enabled:
        return application

    if enabled:
        value = (2).to_bytes(4, "little") + bytes(8)
    else:
        timestamp = time.time_ns() // 100 + 116444736000000000

        value = (
            (3).to_bytes(4, "little")
            + timestamp.to_bytes(8, "little")
        )

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        run_path,
        0,
        winreg.KEY_READ
    ) as key:
        latest_command, latest_type = winreg.QueryValueEx(key, name)

        if latest_command != command or latest_type != value_type:
            raise ValueError("Startup configuration has changed.")

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        approved_path,
        0,
        winreg.KEY_READ
        | winreg.KEY_SET_VALUE
        | winreg.KEY_WOW64_64KEY
    ) as key:

        latest_value, latest_type = winreg.QueryValueEx(key, name)

        if latest_type != current_type or latest_value != current_value:
            raise ValueError("Startup state has changed. Please refresh.")

        winreg.SetValueEx(
            key,
            name,
            0,
            winreg.REG_BINARY,
            value
        )

        verified_value, verified_type = winreg.QueryValueEx(
            key,
            name
        )

        if verified_type != winreg.REG_BINARY or verified_value != value:
            raise RuntimeError("Unable to verify startup state.")

    application["enabled"] = enabled

    return application