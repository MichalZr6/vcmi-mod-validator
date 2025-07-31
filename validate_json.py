import os
import re
import json
import difflib
import inspect
import argparse
import urllib.parse

import json5
import jsonschema
from jsonschema import RefResolver
from jsonschema.validators import validator_for

from pathlib import Path
from copy import deepcopy


def print_and_log(msg: str):
	if LOCAL_MODE and LOG_FILE_PATH:
		with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
			f.write(msg + "\n")
	print(msg)


def find_line_number(pattern, lines):
	"""
	Finds the line number of the first line in `lines` that matches
	the given regex pattern.

	Args:
		pattern (str): The regex pattern to search for.
		lines (list): The list of lines to search within.

	Returns:
		int: The 1-based line number of the first matching line, or 0 if no
		match is found.
	"""
	for idx, line in enumerate(lines, start=1):
		if re.search(pattern, line):
			return idx
	return 0


def strip_comments(content: str) -> str:
	"""
	Removes // and /* */ comments from JSON-like content without affecting
	string literals.
	"""
	result = []
	in_string = False
	in_single_line_comment = False
	in_multi_line_comment = False
	i = 0
	while i < len(content):
		char = content[i]
		next_char = content[i + 1] if i + 1 < len(content) else ''

		if in_single_line_comment:
			if char == '\n':
				in_single_line_comment = False
				result.append(char)
			i += 1
			continue

		if in_multi_line_comment:
			if char == '*' and next_char == '/':
				in_multi_line_comment = False
				i += 2
			else:
				i += 1
			continue

		if char == '"' and not in_string:
			in_string = True
			result.append(char)
			i += 1
			continue
		elif char == '"' and in_string:
			# Check for escaped quote
			backslash_count = 0
			j = i - 1
			while j >= 0 and content[j] == '\\':
				backslash_count += 1
				j -= 1
			if backslash_count % 2 == 0:
				in_string = False
			result.append(char)
			i += 1
			continue

		if not in_string:
			if char == '/' and next_char == '/':
				in_single_line_comment = True
				i += 2
				continue
			elif char == '/' and next_char == '*':
				in_multi_line_comment = True
				i += 2
				continue

		result.append(char)
		i += 1

	return ''.join(result)


def load_and_parse_json(file_path: str) -> tuple:
	"""
	Reads a JSON file (local or remote) and extracts its content
	into a list of lines and a dictionary of JSON entries.

	Args:
		file_path (str): Path or URL to the JSON file.

	Returns:
		tuple: (raw_lines, json_entries, status)
	"""
	try:
		if file_path.startswith("http://") or file_path.startswith("https://"):
			with urllib.request.urlopen(file_path) as response:
				raw = response.read().decode("utf-8")
			lines = raw.splitlines(keepends=True)
			status = ""
		else:
			with open(file_path, 'r', encoding='utf-8') as file:
				lines = file.readlines()
			status = ""
			lines, status = ensure_json_format(lines)

		content = "".join(lines)
		stripped_content = strip_comments(content)
		json_data = json5.loads(stripped_content)

		if status:
			status = status + '\n'

		if VERBOSE:
			status = status + f"✅ {file_path} - loaded.\n"

		return lines, json_data, status

	except FileNotFoundError:
		status = f"❌ load_and_parse_json: File not found: {file_path}"
	except json.JSONDecodeError as e:
		status = f"❌ JSONDecodeError: {e.msg} at line {e.lineno} \
		column {e.colno} for file {file_path}"
	except ValueError as e:
		status = f"❌ load_and_parse_json: Invalid JSON5 \
			format in file {file_path}: {shorten_message(e)}"
	except Exception as e:
		status = f"❌ load_and_parse_json: Unexpected error while \
			reading JSON file {file_path}: {shorten_message(e)}"

	return [], {}, status


def save_to_json_file(lines: list, file_path: str):
	try:
		with open(file_path, 'w', encoding='utf-8', newline='\n') as file:
			file.writelines(lines)

	except Exception as e:
		print_and_log(f"\tERROR: {inspect.currentframe().f_code.co_name}: \
			Failed to save file {file_path}: {shorten_message(e)}")


def try_autofix_json_formatting(lines: list, file_path: str):
	if LOCAL_MODE:
		save_to_json_file(lines, file_path)
	elif AUTOFIX:
		print_and_log("AUTOFIX global variable is set to True but LOCAL_MODE is False \
			- autofixing is not going to be applied.")


def ensure_json_format(lines: list) -> tuple:
	"""
	Ensures proper formatting for a JSON file's lines.

	Returns:
		tuple: (modified_lines, status_message)
	"""
	if not lines:
		return lines, "❌ Empty input lines"

	if AUTOFIX and LOCAL_MODE:
		icon = "🔧"
	else:
		icon = "⚠️"

	formatted_lines = []
	messages = []

	modified_lines = []  # indices of modified lines
	modified_lines_LF = []
	for idx, line in enumerate(lines):
		original_line = line

		# Normalize line endings
		line = line.replace('\r\n', '\n').replace('\r', '\n')
		if line != original_line:
			modified_lines_LF.append(idx + 1)

		# Remove spaces before comma after ] or } or "
		line = re.sub(r'([}\]"]) +,', r'\1,', line)
		if line != original_line:
			modified_lines.append(idx + 1)

		formatted_lines.append(line)

	if modified_lines_LF:
		messages.append(f"{icon} Fix CRLF line ending to LF \
			on lines: {modified_lines_LF}")

	if modified_lines:
		messages.append(f"{icon} Remove trailing space before ',' \
			on lines: {modified_lines}")

	# Add final newline if missing
	if not formatted_lines[-1].endswith('\n'):
		formatted_lines[-1] += '\n'
		messages.append(f"{icon} Append trailing newline at the end of file")

	# Align " : formatting
	modified_lines.clear()
	for i, line in enumerate(formatted_lines):
		new_line = re.sub(r'"\s*:\s*', '" : ', line)
		if new_line != line:
			modified_lines.append(i + 1)
			formatted_lines[i] = new_line

	if modified_lines:
		messages.append(f"{icon} Fix key-value spacing on lines: {modified_lines}")

	i = 0
	modified_lines.clear()
	while i < len(formatted_lines) - 1:
		current = formatted_lines[i].rstrip()
		next_line = formatted_lines[i + 1].lstrip()
		if re.search(r'"\s*:\s*$', current) and re.match(r'^[{\["]', next_line):
			formatted_lines[i] = current + " " + next_line
			del formatted_lines[i + 1]
			modified_lines.append(i + 1)
		else:
			i += 1

	if modified_lines:
		messages.append(f"{icon} Join multi-line brace on lines: {modified_lines}")

	# Recombine and split for consistency
	content = "".join(formatted_lines)
	formatted_lines = content.splitlines(keepends=True)

	# Compare with original
	if formatted_lines != lines:
		status = "⚠️ Formatting issues"
	else:
		status = "✅ No formatting issues\n"

	if messages:
		return formatted_lines, f"{status}:\n  " + "\n  ".join(messages)
	else:
		return formatted_lines, status


def is_valid_version(ver: str) -> bool:
	return bool(re.fullmatch(VERSION_PATTERN, ver))


def parse_version(ver: str) -> tuple:
	return tuple(int(part) for part in ver.split("."))


def get_latest_changelog_version(changelog: dict) -> str | None:
	"""Return the latest valid version string from changelog dict,
		or None if no valid ones exist."""
	valid_keys = [k for k in changelog.keys() if is_valid_version(k)]
	if not valid_keys:
		return None
	return sorted(valid_keys, key=parse_version)[-1]


def fix_version_in_lines(lines: list[str], new_version: str) -> bool:
	"""Find and replace the version line in the given lines.
	Returns True if successful."""
	version_line_num = find_line_number(r'"version"\s*:', lines)
	if version_line_num:
		lines[version_line_num - 1] = re.sub(
			r'"[0-9]+\.[0-9]+\.[0-9]+"',
			f'"{new_version}"',
			lines[version_line_num - 1]
		)
		return True
	return False


def load_repo_tree() -> bool:
	global REPO_TREE
	try:
		response = urllib.request.urlopen(VCMI_TREE_URL).read()
		REPO_TREE = json5.loads(response)["tree"]
		return True
	except Exception as e:
		print_and_log(f"❌ Failed to load VCMI repo tree: {shorten_message(e)}")
		return False


def get_schema(key: str) -> dict:
	assert SCHEMA_CACHE is not None, 'Load schemas first'

	if key not in ENTRY_SCHEMA_MAP:
		raise KeyError(f"No schema mapped for key: {key}")

	schema_filename = ENTRY_SCHEMA_MAP[key]
	if LOCAL_MODE and os.path.isdir(SCHEMAS_PATH):
		schema_path = (SCHEMAS_PATH / schema_filename).resolve().as_uri()
	else:
		schema_path = f"{SCHEMA_BASE_URL}{schema_filename}"

	if schema_path in SCHEMA_CACHE:
		return SCHEMA_CACHE[schema_path]

	raise FileNotFoundError(f"Schema not loaded or missing from \
		SCHEMA_CACHE: {schema_path}")


def shorten_message(msg: str, limit: int = 260, head: int = 130,
					tail: int = 130) -> str:
	if len(msg) > limit:
		return msg[:head] + " (trimmed...) " + msg[-tail:]
	return msg


def validate_json_schema(json_entries: dict, json_path: str,
						schema_dict: dict) -> str:
	assert SCHEMA_CACHE is not None, "Schema store must be provided"

	try:
		base_uri = schema_dict.get("$id")

		resolver = RefResolver(base_uri=base_uri, referrer=schema_dict,
								store=SCHEMA_CACHE)

		validator_class = validator_for(schema_dict)
		validator_class.check_schema(schema_dict)
		validator = validator_class(schema_dict, resolver=resolver)

		validator.validate(instance=json_entries)

		return "✅ Schema validation passed"

	except jsonschema.exceptions.ValidationError as e:
		path_str = " → ".join(map(str, e.absolute_path)) or "<root>"
		error_msg = e.message

		# Suggest alternative key for unknown fields
		if e.validator == "additionalProperties":
			unexpected = e.message.split("'")[1]
			allowed_keys = list(e.schema.get("properties", {}).keys())
			close_matches = difflib.get_close_matches(unexpected, allowed_keys,
								n=1, cutoff=0.75)
			if close_matches:
				suggestion = close_matches[0]
				error_msg += f" (Did you mean '{suggestion}'?)"

		schema_name = schema_dict.get("$id", "<unnamed schema>").rsplit("/", 1)[-1]
		return f"❌ Schema {schema_name} validation error: {error_msg} at path: {path_str}"

	except Exception as e:
		msg = shorten_message(str(e))
		return f"❌ Unexpected error during schema validation \
			for file {json_path}: {e.__class__.__name__}: {msg}"


def validate_and_fix_mod_version(lines, json_entries, file_path) -> str:
	"""
	Validates and optionally fixes 'version' in mod.json based
	on changelog (if present).
	"""
	try:
		version = json_entries.get("version")
		# We skip check if 'version' key exists. Will be caught by 
		# schema validator as it is required field.
		if not version:
			return "⚠️ Empty 'version' value. VCMI will treat it as 1.0"
		if not is_valid_version(version):
			return f"❌ Invalid 'version': {version} \
				(expected number_A.number_B.number_C format)"

		changelog = json_entries.get("changelog")
		if isinstance(changelog, dict) and changelog:
			latest_version = get_latest_changelog_version(changelog)
			if latest_version and parse_version(version) != parse_version(latest_version):
				if fix_version_in_lines(lines, latest_version):
					return f"⚠️ Version mismatch — auto-fixing version \
						in {file_path}: {version} -> {latest_version}"

		return "✅ Version check: OK"

	except Exception as e:
		return (f"❌ Unexpected error during version validation:\
			\t{inspect.currentframe().f_code.co_name}:"
				f"Error processing {file_path}: {shorten_message(e.message)}")


def flatten_nested_lists(obj):
	if isinstance(obj, dict):
		return {k: flatten_nested_lists(v) for k, v in obj.items()}
	elif isinstance(obj, list) and all(isinstance(i, list) for i in obj):
		# Only flatten if it's a list of lists (and not strings)
		return [item for sublist in obj for item in sublist]
	return obj


def collect_and_parse_H3_config_files(lookup_key: str = "") -> \
	tuple[dict[str, dict], list[tuple[str, str]]]:
	"""
	Loads and parses JSON patch files from H3 base patches directory (PATCHES_DIR).
	Each file is expected to match a schema entry name
	(e.g. 'creatures.json' -> 'creatures').

	Parameters:
	- lookup_key (str): Optional. If provided, only loads
	  the patch file matching this key (e.g. 'creatures').
	  If empty, loads all matching patch files.

	Returns:
	- tuple:
	  - json_files_data (dict[str, dict]): Dictionary of loaded patch data with
	  keys derived from filenames (without .json).
	  - failed_paths (list[tuple[str, str]]): List of (file_path, error message)
	  for files that failed to load or parse.
	"""
	json_files_data = {}
	failed_paths = []

	if not PATCHES_DIR or not os.path.isdir(PATCHES_DIR):
		return {}, [("PATCHES_DIR is not a valid directory.",
			f"PATCHES_DIR: {PATCHES_DIR}")]

	for root, _, files in os.walk(PATCHES_DIR):
		for fname in files:
			if not fname.endswith(".json"):
				continue

			basename = fname[:-5]
			if lookup_key and basename != lookup_key:
				continue

			fp = os.path.join(root, fname)
			try:
				if VERBOSE:
					print_and_log(f"Reading: {fp}")
				_, json_data, status = load_and_parse_json(fp)
				if status[0] != "❌":
					json_files_data = json_data
				else:
					failed_paths.append((fp, status))
			except Exception as e:
				failed_paths.append((fp, f"{e.__class__.__name__}: {shorten_message(str(e))}"))

	return json_files_data, failed_paths


def collect_and_parse_local_base_config_files(json_files_data: dict,
				lookup_key: str = "") -> tuple[dict[str, dict], list[tuple[str, str]]]:
	"""
	Loads and parses local base configuration JSON files from BASE_CONFIG_PATH.
	If `lookup_key` is provided, only loads data for that specific key
	(e.g. 'creatures').
	Otherwise, iterates over all keys in ENTRY_SCHEMA_MAP.

	Returns:
	- tuple:
		- json_files_data (dict[str, dict]): Updated input dictionary
		with parsed data merged in.
		- failed_paths (list[tuple[str, str]]): List of (file_path, error message)
		for failed loads.
	"""
	failed_paths = []

	if not BASE_CONFIG_PATH or not os.path.isdir(BASE_CONFIG_PATH):
		print_and_log("⚠️ BASE_CONFIG_PATH is not a valid directory. \
			Will use remote logic to collect base data.")
		return collect_and_parse_base_config_files(json_files_data, lookup_key)

	target_keys = [lookup_key] if lookup_key else list(ENTRY_SCHEMA_MAP)

	for key in target_keys:
		json_files_data.setdefault(key, {})

	for root, _, files in os.walk(BASE_CONFIG_PATH):
		for fname in files:
			if not fname.endswith(".json"):
				continue
			fp = os.path.join(root, fname)
			if 'schemas' in fp:
				continue

			is_settings_file = "gameConfig" in fp
			for key in target_keys:
				if key in fp or is_settings_file:
					try:
						if VERBOSE:
							print_and_log(f"Reading: {fp}")
						_, json_data, status = load_and_parse_json(fp)
						if status[0] == "❌":
							failed_paths.append((fp, status))
							continue
					except Exception as e:
						failed_paths.append((fp, f"{e.__class__.__name__}: \
							{shorten_message(str(e))}"))
						continue

					target_key = "settings" if is_settings_file else key
					json_files_data.setdefault(target_key, {})
					json_files_data[target_key].update(json_data)

	return json_files_data, failed_paths


def collect_and_parse_base_config_files(json_files_data: dict,
				lookup_key: str = "") -> tuple[dict[str, dict], list[tuple[str, str]]]:
	"""
	Fetches and parses base configuration JSON files from the VCMI repository.

	Parameters:
	- json_files_data (dict): A dictionary of parsed JSON data per key
		(e.g., "creatures", "objects", etc.)
		which will be updated with the fetched base configuration data.
	- lookup_key (str): Optional. If provided, only base config files related
		to this key will be fetched and parsed.
		If empty, config files for all keys defined in ENTRY_SCHEMA_MAP will be processed.

	Returns:
	- tuple:
		- Updated json_files_data (dict[str, dict]): Dictionary containing merged
		base configuration data.
		- failed_paths (list[tuple[str, str]]): List of (url, error message) for
		paths that failed to load or parse.
	"""

	failed_paths = []
	assert REPO_TREE is not None, "VCMI repo tree must be provided"

	all_paths = {entry["path"]: entry["type"] for entry in REPO_TREE}

	keys_to_check = [lookup_key] if lookup_key else list(ENTRY_SCHEMA_MAP)

	json_file_paths = [
		path for path, type_ in all_paths.items()
		if path.startswith("config/")
		and path.endswith(".json")
		and 'schemas' not in path
		and any(f"config/{key}/" in path or path == f"config/{key}.json" or
			(key == "settings" and "gameConfig" in path) for key in keys_to_check)
	]

	for fp in json_file_paths:
		full_url = f"{VCMI_URL}/{fp}"

		is_settings_file = "gameConfig" in fp
		for key in keys_to_check:
			if key in fp or is_settings_file:
				try:
					if VERBOSE:
						print_and_log(f"Reading: {full_url}")
					_, json_data, status = load_and_parse_json(full_url)
					if status.startswith("❌"):
						failed_paths.append((full_url, status))
						continue
				except Exception as e:
					failed_paths.append((full_url, f"{e.__class__.__name__}: \
						{shorten_message(str(e))}"))
					continue

				target_key = "settings" if is_settings_file else key
				json_files_data.setdefault(target_key, {})
				json_files_data[target_key].update(json_data)

	return json_files_data, failed_paths


def try_parse_relative_json(relative_path: str, base_dir: str, 
							json_files_data: dict, failed_paths: set) -> bool:
	if not os.path.splitext(relative_path)[1]:
		relative_path += ".json"

	# 1. Try exact relative path
	candidate_paths = [os.path.normpath(os.path.join(base_dir, relative_path))]

	# 2. Try common case variants of known folders (Content/config, etc.)
	subfolders_to_try = ["content", "Content", "config", "Config"]
	for subfolder in subfolders_to_try:
		alt_path = os.path.normpath(os.path.join(base_dir, subfolder, relative_path))
		candidate_paths.append(alt_path)

	# 3. Use first one that exists
	candidate_path = next((p for p in candidate_paths if os.path.isfile(p)), None)

	# 4. Fallback: case-insensitive filename match
	if not candidate_path:
		basename = os.path.basename(relative_path)
		for root, _, files in os.walk(base_dir):
			lowered = [f.lower() for f in files]
			if basename.lower() in lowered:
				original = files[lowered.index(basename.lower())]
				suggested_path = os.path.join(root, original)
				print_and_log(f"⚠️ File at given path: {relative_path} was not found. \
					Did you mean: {suggested_path}?")
				candidate_path = suggested_path
				break

	if candidate_path:
		try:
			lines, json_data, status = load_and_parse_json(candidate_path)
			if status[0] != "❌":
				if "🔧" in status:
					try_autofix_json_formatting(lines, candidate_path)

				if candidate_path not in json_files_data:
					json_files_data[candidate_path] = {}

				for key, value in json_data.items():
					if key in json_files_data[candidate_path]:
						json_files_data[candidate_path][key] = deep_merge(
							json_files_data[candidate_path][key], value
						)
					else:
						json_files_data[candidate_path][key] = value
				return True
			else:
				failed_paths.add((candidate_path, status))
		except Exception as e:
			failed_paths.add((candidate_path, f"{e.__class__.__name__}: \
				{shorten_message(e.args[0])}"))
		return False

	# If no file was resolved
	failed_paths.add((relative_path, f"❌ File not found in {base_dir}"))
	return False


def write_patch_file(name: str, data: dict):
	if not data:
		return
	PATCHES_DIR.mkdir(parents=True, exist_ok=True)
	out_path = PATCHES_DIR / f"{name}.json"
	with open(out_path, "w", encoding="utf-8") as f:
		json.dump(data, f, indent='\t')
	print_and_log(f"✅ Wrote patch file: {out_path}")


def extract_patch_data(h3_data: dict, base_data: dict) -> dict:
	def diff_dict(h3_entry, base_entry):
		patch = {}
		for key, h3_value in h3_entry.items():
			if key not in base_entry:
				patch[key] = h3_value
			else:
				base_value = base_entry[key]
				if isinstance(h3_value, dict) and isinstance(base_value, dict):
					sub_diff = diff_dict(h3_value, base_value)
					if sub_diff:
						patch[key] = sub_diff
				elif h3_value != base_value:
					patch[key] = h3_value
		return patch

	result = {}
	for path, base_entry in base_data.items():
		for sub_entry_key, sub_entry in base_entry.items():
			for h3_path, h3_entry in h3_data.items():
				h3_sub_entry_key = \
					os.path.splitext(os.path.basename(h3_path))[0].split(".")[-1].lower()
				if sub_entry_key.lower() == h3_sub_entry_key:
					patch = diff_dict(h3_entry, sub_entry)
					if patch:
						result[sub_entry_key] = patch
						break

	return result


def collect_and_parse_extracted_config_files() -> tuple[dict, list]:
	json_files_data = {}
	failed_paths = []

	def get_data(key: str, fp: str, is_dir: bool):
		try:
			_, json_data, status = load_and_parse_json(fp)
			if status[0] != "❌":
				if is_dir:
					dir_key = os.path.dirname(fp)
					if dir_key not in json_files_data[key]:
						json_files_data[key][dir_key] = {}
					json_files_data[key][dir_key].update(json_data)
				else:
					json_files_data[key][fp] = json_data
			else:
				failed_paths.append((fp, status))
		except Exception as e:
			failed_paths.append((fp, f"{e.__class__.__name__}: \
				{shorten_message(e.args[0])}"))

	for key in ENTRY_SCHEMA_MAP:
		json_files_data[key] = {}
		if VERBOSE:
			print_and_log(f"Loading extracted H3 config data for {key}")

		path = os.path.join(EXTRACTED_CONFIG_DIR, key)
		if os.path.isdir(path):
			# Get all JSON data from folders like 'creatures', 'factions', 'spells', etc.
			for root, _, files in os.walk(path):
				for fname in files:
					if fname.endswith(".json"):
						fp = os.path.join(root, fname)
						get_data(key, fp, True)
		elif os.path.isfile(path + '.json'):
			get_data(key, path + '.json', False)

	return json_files_data, failed_paths


def extract_all_patches():
	h3_base_data = {}
	h3_base_data, errors = collect_and_parse_extracted_config_files(h3_base_data)
	for path, reason in errors:
		print_and_log(f"❌ {path} - {reason}")
	if errors:
		return

	vcmi_base_data = {}
	vcmi_base_data, errors = collect_and_parse_base_config_files(vcmi_base_data)
	for path, reason in errors:
		print_and_log(f"❌ {path} - {reason}")
	if errors:
		return

	for key in h3_base_data:
		h3_entries = h3_base_data.get(key, {})
		vcmi_entries = vcmi_base_data.get(key, {})
		patch = extract_patch_data(h3_entries, vcmi_entries)
		write_patch_file(key, patch)


def collect_and_parse_json_files(json_files_data: dict, 
								mod_json_data: dict, base_dir: str) -> tuple[dict, set]:
	if not json_files_data:
		json_files_data = {key: {} for key in ENTRY_SCHEMA_MAP}
	failed_paths = set()

	def looks_like_path(s: str) -> bool:
		if "http" in s.lower():
			return False
		if "<" in s or ">" in s:  # avoid HTML fragments
			return False
		if any(c.isspace() for c in s):  # avoid multi-word descriptions
			return False
		if len(s) > 100:  # arbitrary threshold
			return False
		return '/' in s

	for key, entry in mod_json_data.items():
		if key not in ENTRY_SCHEMA_MAP:
			continue
		if isinstance(entry, list):
			for value in entry:
				if looks_like_path(value):
					try_parse_relative_json(value, base_dir, json_files_data[key], failed_paths)
		elif isinstance(entry, dict):
			json_files_data[key] = entry	

	return json_files_data, failed_paths


def deep_merge(base, override):
	if isinstance(base, dict) and isinstance(override, dict):
		merged = deepcopy(base)
		for key, override_val in override.items():
			base_val = base.get(key)
			if key in base:
				if isinstance(base_val, dict) and isinstance(override_val, dict):
					merged[key] = deep_merge(base_val, override_val)
				elif isinstance(base_val, list) and isinstance(override_val, list):
					merged[key] = deep_merge(base_val, override_val)
				elif type(base_val) == type(override_val):
					merged[key] = override_val
				else:
					merged[key] = override_val  # prefer override on mismatch
			else:
				merged[key] = override_val
		return merged

	elif isinstance(base, list) and isinstance(override, list):
		result = []
		seen = []
		for item in base + override:
			try:
				if item not in seen:
					seen.append(item)
					result.append(item)
			except TypeError:
				result.append(item)
		return result

	return deepcopy(override)


def remove_null_base_entries(data):
	if isinstance(data, dict):
		return {
			k: remove_null_base_entries(v)
			for k, v in data.items()
			if not (k == "base" and v is None)
		}
	elif isinstance(data, list):
		return [remove_null_base_entries(item) for item in data]
	else:
		return data


def resolve_recursive_base(data):
	"""
	Recursively resolves "base" references in a dictionary.
	If an entry has a "base" key pointing to another entry, merge it.
	"""
	if not isinstance(data, dict):
		return data

	resolved = {}

	for key, value in data.items():
		if not isinstance(value, dict):
			resolved[key] = value
			continue

		base_key = value.get("base")
		merged = deepcopy(value)

		if isinstance(base_key, str) and base_key in data:
			base_val = resolve_recursive_base(data[base_key])
			merged.pop("base")
			merged = deep_merge(base_val, merged)

		resolved[key] = resolve_recursive_base(merged)

	return resolved


def merge_mod_data(entry_id: str, entry: dict, merged_data: dict) -> dict:
	normalized_id = normalize_scoped_id(entry_id)
	merged_data[normalized_id] = deep_merge(merged_data.get(normalized_id, {}), entry)
	return merged_data


def normalize_scoped_id(id_str: str) -> str:
	# Strip the part before the colon (VCMI style: modnamespace:id)
	return id_str.split(":", 1)[-1]


def print_status(status: str | list[str], additional_info=""):
	if isinstance(status, list):
		for s in status: print_and_log(f"{s}{additional_info}")
	else:
		print_and_log(f"{status}{additional_info}")


def has_error(status: str | list[str]) -> bool:
	if isinstance(status, list): return any("❌" in s for s in status)
	return "❌" in status


def load_and_validate_schemas_local() -> list[str]:
	errors = []
	global SCHEMA_CACHE

	if not SCHEMAS_PATH or not os.path.isdir(SCHEMAS_PATH):
		print_and_log("⚠️ SCHEMAS_PATH is not a valid directory. \
			Will use remote logic to collect schema files.")
		return load_and_validate_schemas()

	for file_path in SCHEMAS_PATH.glob("*.json"):
		schema_id = str(file_path.resolve().as_uri())

		if schema_id in SCHEMA_CACHE:
			continue

		try:
			with open(file_path, "r", encoding="utf-8") as f:
				content = f.read()
			stripped = strip_comments(content)
			json_data = json5.loads(stripped)
			json_data["$id"] = schema_id
			SCHEMA_CACHE[schema_id] = json_data
			if VERBOSE:
				print(f"Schema: {schema_id} - loaded.")
		except json.JSONDecodeError as e:
			errors.append(f"{file_path}: JSONDecodeError: {e.msg} \
				at line {e.lineno} column {e.colno}")
		except Exception as e:
			errors.append(f"{file_path}: {e.__class__.__name__}: \
				{shorten_message(str(e))}")

	return errors


def load_and_validate_schemas() -> list[str]:
	errors = []
	global SCHEMA_CACHE

	assert REPO_TREE is not None, "VCMI repo tree must be provided"

	# Find all .json schema files under config/schemas/
	schema_paths = [
		entry["path"] for entry in REPO_TREE
		if entry["path"].startswith("config/schemas/") and entry["path"].endswith(".json")
	]

	for path in schema_paths:
		url = f"{VCMI_URL}/{path}"

		if url in SCHEMA_CACHE:
			continue

		try:
			_, json_data, status = load_and_parse_json(url)
			json_data["$id"] = url
			SCHEMA_CACHE[url] = json_data
			if "❌" in status:
				errors.append(f"Schema {url} validation error: {status}")

		except json.JSONDecodeError as e:
			errors.append(f"{url}: JSONDecodeError: {e.msg} at line \
				{e.lineno} column {e.colno}")
		except Exception as e:
			errors.append(f"{url}: {e.__class__.__name__}: {e}")

	return errors


def apply_inheritance(data: dict, context: str) -> dict:
	inheritance_funcs = {
		"objects": inherit_object_types,
		"skills": inherit_skill_levels,
		"spells": inherit_spell_levels,
		"heroes": inherit_hero_specialty,
		"towns": inherit_town_buildings,
	}

	func = inheritance_funcs.get(context)
	return func(data) if func else data


def inherit_spell_levels(data: dict) -> dict:
	levels = data.get("levels")
	if not isinstance(levels, dict):
		return data

	base = levels.get("base")
	if not isinstance(base, dict):
		return data

	for level_name in ("none", "basic", "advanced", "expert"):
		level_data = levels.get(level_name)
		if isinstance(level_data, dict):
			levels[level_name] = deep_merge(base, level_data)

	data["levels"] = levels
	return data


def inherit_skill_levels(data: dict) -> dict:
	base = data.get("base")
	if not isinstance(base, dict):
		return data

	for level_name in ("basic", "advanced", "expert"):
		level_data = data.get(level_name)
		if isinstance(level_data, dict):
			data[level_name] = deep_merge(base, level_data)

	return data


def inherit_object_types(data: dict) -> dict:
	if not isinstance(data, dict):
		return data

	types = data.get("types")
	base = data.get("base")
	sub_objects = data.get("subObjects")

	if not isinstance(types, dict):
		return data

	for type_name, type_data in types.items():
		if not isinstance(type_data, dict):
			continue

		# First: merge from subObjects[index] if available
		if isinstance(sub_objects, list) and isinstance(type_data.get("index"), int):
			idx = type_data["index"]
			if 0 <= idx < len(sub_objects):
				type_data = deep_merge(sub_objects[idx], type_data)

		# Second: merge from base
		if isinstance(base, dict):
			type_data = deep_merge(base, type_data)

		# Third: merge into templates[...], if templates and base exist
		templates = type_data.get("templates")
		type_base = type_data.get("base")
		if isinstance(templates, dict) and isinstance(type_base, dict):
			for tmpl_key, tmpl_val in templates.items():
				if isinstance(tmpl_val, dict):
					templates[tmpl_key] = deep_merge(type_base, tmpl_val)
			type_data["templates"] = templates

		# Assign back
		types[type_name] = type_data

	# Remove subObjects after merging
	data.pop("subObjects", None)

	return data


def inherit_hero_specialty(data: dict) -> dict:
	specialty = data.get("specialty")
	if not isinstance(specialty, dict):
		return data

	base = specialty.get("base")
	bonuses = specialty.get("bonuses")

	if not isinstance(base, dict) or not isinstance(bonuses, dict):
		return data

	for key, val in bonuses.items():
		if isinstance(val, dict):
			bonuses[key] = deep_merge(base, val)

	specialty["bonuses"] = bonuses
	data["specialty"] = specialty
	return data


def inherit_town_buildings(data: dict, buildings_library: dict) -> dict:
	town = data.get("town")
	if not isinstance(town, dict):
		return data

	buildings = town.get("buildings")
	if not isinstance(buildings, dict):
		return data

	for name, building in buildings.items():
		if not isinstance(building, dict):
			continue

		# Inherit from global building definition
		base_def = buildings_library.get(name)
		if isinstance(base_def, dict):
			building = deep_merge(base_def, building)

		# Inherit from building["type"] if it matches a global def
		building_type = building.get("type")
		if isinstance(building_type, str):
			type_def = buildings_library.get(building_type)
			if isinstance(type_def, dict):
				building = deep_merge(type_def, building)

		# MOD COMPAT: convert legacy format into modern config
		if "onVisitBonuses" in building:
			config = building.setdefault("configuration", {})
			config.setdefault("visitMode", "bonus")
			config.setdefault("rewards", [{}])
			config["rewards"][0].setdefault("message", building.get("description"))
			config["rewards"][0].setdefault("bonuses", building["onVisitBonuses"])

		buildings[name] = building

	town["buildings"] = buildings
	data["town"] = town
	return data


def validate_settings_keys(mod_patch: dict, base_settings: dict,
							path: str = "settings"):
	missing = []
	for key, value in mod_patch.items():
		full_path = f"{path}.{key}"
		if key not in base_settings:
			missing.append(full_path)
		elif isinstance(value, dict) and isinstance(base_settings.get(key), dict):
			missing += validate_settings_keys(value, base_settings[key], full_path)
	return missing


def process_json_files(mod_root: str):
	validation_failed = False
	total_files = 0
	total_errors = 0
	total_fixes = 0
	total_warnings = 0

	def track_status(status: str, label: str = ""):
		nonlocal validation_failed, total_errors, total_fixes, total_warnings
		if not status:
			return
		validation_failed |= has_error(status)
		if "❌" in status:
			total_errors += 1
		if "⚠️" in status:
			total_warnings += 1
		if "🔧" in status:
			total_fixes += 1
		if VERBOSE or "❌" in status:
			print_status(status, label)

	print_and_log("Collecting mod's .json paths from input directory...")
	mod_json_paths = []
	other_json_paths = []
	for root, _, files in os.walk(mod_root):
		for file in files:
			if file == "mod.json":
				mod_json_paths.append(os.path.join(root, file))
			elif file.endswith(".json"):
				other_json_paths.append(os.path.join(root, file))

	if not LOCAL_MODE or not os.path.isdir(SCHEMAS_PATH) \
		or not os.path.isdir(BASE_PATH):
		print_and_log("Loading main repo tree...")
		if not load_repo_tree():
			print_and_log("❌ Failed to load repo tree.")
			return

	print_and_log("Loading schema files...")
	if LOCAL_MODE:
		schema_errors = load_and_validate_schemas_local()
	else:
		schema_errors = load_and_validate_schemas()

	if schema_errors:
		for error in schema_errors:
			print_and_log(error)
		print_and_log("Failed to parse schemas. Aborting.")
		return

	print_and_log("Validating mod.json files...")
	mod_json_files_data = {}
	for mod_json_path in mod_json_paths:
		total_files += 1
		mod_lines, mod_json_data, status = load_and_parse_json(mod_json_path)
		if "🔧" in status:
			try_autofix_json_formatting(mod_lines, mod_json_path)
		mod_name = mod_json_data.get("name", os.path.dirname(mod_json_path))
		print_and_log(f"\n🔍 Validating mod: {mod_name}")

		status += validate_json_schema(mod_json_data, mod_json_path, get_schema('mod'))
		track_status(status)

		version_status = validate_and_fix_mod_version(mod_lines, mod_json_data,
														mod_json_path)
		if "🔧" in version_status:
			try_autofix_json_formatting(mod_lines, mod_json_path)
		track_status(version_status)

		mod_json_files_data, parse_errors = \
			collect_and_parse_json_files(mod_json_files_data, mod_json_data,
											os.path.dirname(mod_json_path))
		for path, reason in parse_errors:
			track_status(f"❌ {path} - {reason}")

	# Build merged full config by combining mod and base files
	print_and_log("Validating all mod's files merged with base config files...")
	base_json_files_data = {}
	for key in ENTRY_SCHEMA_MAP:
		mod_data = mod_json_files_data[key]
		if mod_data:
			print_and_log(f"Loading needed base VCMI config files for '{key}'")
			if LOCAL_MODE:
				base_json_files_data, base_errors = \
					collect_and_parse_local_base_config_files(base_json_files_data, key)
			else:
				base_json_files_data, base_errors = \
					collect_and_parse_base_config_files(base_json_files_data, key)

			for path, reason in base_errors:
				track_status(f"❌ {path} - {reason}")

			print_and_log(f"Loading needed H3 base config patches for '{key}'")
			h3_base_data, h3_errors = collect_and_parse_H3_config_files(key)
			for path, reason in h3_errors:
				track_status(f"❌ {path} - {reason}")
			if h3_errors:
				print_and_log("H3 patches loading failed. Aborting.")
				return

			print_and_log(f"Validating all mod's files merged with base config files \
							for '{key}'")
			merged_data = {}
			schema_dict = get_schema(key)

			for base_key, base_entry_data in base_json_files_data[key].items():
				merged_data[base_key] = deepcopy(base_entry_data)

			if key == "settings":
				missing_keys = validate_settings_keys(mod_data, base_json_files_data[key])
				if missing_keys:
					for k in missing_keys:
						track_status(f"❌ Unknown settings key '{k}' used in mod", f" at {k}")
				continue

			for h3_key, h3_base_entry_data in h3_base_data.items():
				merged_data[h3_key] = deep_merge(merged_data.get(h3_key, {}), h3_base_entry_data)
				# Inject gainChance when missing to satisfy required field in schema
				if key == "skills" and "gainChance" not in merged_data:
					merged_data["gainChance"] = {"might": 0, "magic": 0}

			for _, mod_entry_data in mod_data.items():
				for entry_id, entry in mod_entry_data.items():
					merge_mod_data(entry_id, entry, merged_data)

			for merged_id, data in merged_data.items():
				data = apply_inheritance(data, key)
				data = resolve_recursive_base(data)
				data = remove_null_base_entries(data)
				status = validate_json_schema(data, '', schema_dict)
				track_status(status, f" for {merged_id}")

	print_and_log("Validating other JSON files...")
	for json_file in other_json_paths:
		total_files += 1
		lines, json_data, status = load_and_parse_json(json_file)
		if "🔧" in status:
			try_autofix_json_formatting(lines, json_file)
		track_status(status)

	print_and_log("\n🔍 Validation summary:")
	print_and_log(f"🧾 Files checked:\t{total_files}")
	print_and_log(f"❌ Errors:\t\t{total_errors}")
	print_and_log(f"⚠️ Warnings:\t\t{total_warnings}")
	if AUTOFIX and LOCAL_MODE:
		print_and_log(f"🔧 Auto-fixes:\t\t{total_fixes}")
	if validation_failed:
		print_and_log("❗ VALIDATION FAILED")
	else:
		if total_files == 0:
			print_and_log("ℹ️  NO FILES FOUND TO VALIDATE")
		else:
			print_and_log("✅ VALIDATION SUCCESSFUL")


# Define input directory and output directory
INPUT_DIR = r"/home/manfred/Programowanie/VCMI/mods/wake-of-gods"
EXTRACTED_CONFIG_DIR = r"/home/manfred/.cache/vcmi/extracted/configuration"
PATCHES_DIR = Path("h3_data/preprocessed_h3_patches")

LOCAL_MODE = True  	# Set to True for local usage. It will load base config files
					# and schemas faster, autofix feature can be enabled
					# but you must provide correct BASE_PATH for VCMI's source directory.
					# Set it to False if you don't have local VCMI source.

# LOCAL_MODE variables:
AUTOFIX = True	# Available only in LOCAL_MODE. Enable this to auto-format
				# validated json files.
				# Converts CRLFs to LFs, ensures trailing line at the end of the file,
				# makes some basic json structure re-formatting
LOG_FILE_PATH = r"/home/manfred/Programowanie/VCMI/vcmi_validator_log.txt"
BASE_PATH = Path("/home/manfred/Programowanie/VCMI/source/")
BASE_CONFIG_PATH = BASE_PATH / "config"
SCHEMAS_PATH = BASE_CONFIG_PATH / "schemas"

# REMOTE_MODE variables:
VCMI_REPO = "MichalZr6/vcmi"
VCMI_BRANCH = "fix_schemas"
VCMI_TREE_URL = f"https://api.github.com/repos/{VCMI_REPO}/git/trees/{VCMI_BRANCH}?recursive=1"
VCMI_URL = f"https://raw.githubusercontent.com/{VCMI_REPO}/{VCMI_BRANCH}"
BASE_CONFIG_URL = f"{VCMI_URL}/config/"
SCHEMA_BASE_URL = f"{BASE_CONFIG_URL}schemas/"


VERBOSE = True

SCHEMA_CACHE = {}
REPO_TREE = []

ENTRY_SCHEMA_MAP = {
	"heroClasses": "heroClass.json",
	"artifacts": "artifact.json",
	"bonuses": "bonus.json",
	"creatures": "creature.json",
	"campaignRegions": "campaignRegion.json",
	"factions": "faction.json",
	"highscoreCreatures": "highscoreCreatures.json",
	"objects": "object.json",
	"heroes": "hero.json",
	"settings": "settings.json",
	"spells": "spell.json",
	"spellSchools": "spellSchool.json",
	"skills": "skill.json",
	"templates": "template.json",
	"scripts": "script.json",
	"battlefields": "battlefield.json",
	"terrains": "terrain.json",
	"rivers": "river.json",
	"roads": "road.json",
	"obstacles": "obstacle.json",
	"biomes": "biome.json",
	"mod": "mod.json"
}

VERSION_PATTERN = r'^(0|[1-9]\d*)\.(0|[1-9]\d*)(\.(0|[1-9]\d*))?$'

if __name__ == "__main__":

	# sys.argv.append("--extract-patches")	# Extracts H3 base game config data. The result of this are
											# config files stripped on vcmi base data.
											# They should be in PATCHES_DIR folder already.
											# Those are needed to run the validation script.
											# Do not uncomment this, until you know what you're doing ;)

	parser = argparse.ArgumentParser(description="Validate mods or extract H3 base config JSONs")
	parser.add_argument(
		"--extract-patches",
		action="store_true",
		help="Extract patch files from preprocessed /get config output"
	)
	args = parser.parse_args()

	if LOCAL_MODE and LOG_FILE_PATH:
		with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
			f.write(f"# Log file created at {LOG_FILE_PATH}\n")

	if args.extract_patches:
		extract_all_patches()
		print_and_log("\nPatch extraction completed.")
	else:
		process_json_files(INPUT_DIR)
		print_and_log("\nValidation completed.")
