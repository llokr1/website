#!/usr/bin/env python3
#
# This a link checker for Kubernetes documentation website.
#
# If the language to check is not English (`en`), we check if you are actually
# using the localized links. For example, if you checking
# `content/zh-cn/docs/foo/bar`, we check if the English version exists AND if the
# Chinese version exists as well.  A checking record is produced if the link
# can use the localized version.
#
# Usage: linkchecker.py -h
#
# Cases handled:
#
# - [foo](#bar)                         : ignored currently
# + [foo](http://bar)                   : insecure links to external site
# + [foo](https://k8s.io/website/...)   : hardcoded site domain name
#
# + [foo](/<lang>/docs/bar/...)  : where <lang> is not 'en'
#   + /<lang>/docs/bar           : contains shortcode, so ignore, or
#   + /<lang>/docs/bar           : is a image link (ignore currently), or
#   + /<lang>/docs/bar           : points to shared (non-localized) page, or
#   + /<lang>/docs/bar.md        : exists for current lang, or
#   + /<lang>/docs/bar/_index.md : exists for current lang, or
#   + /<lang>/docs/bar/          : is a redirect entry, or
#   + /<lang>/docs/bar           : is something we don't understand, then ERR
#
# + [foo](/docs/bar/...)
#   + /docs/bar                : contains shortcode, so ignore, or
#   + /docs/bar                : is a image link (ignore currently), or
#   + /docs/bar                : points to a shared (non-localized) page, or
#   + /docs/bar.md             : exists for current lang, or
#   + /docs/bar/_index.md      : exists for current lang, or
#   + /docs/bar                : is a redirect entry, or
#   + /docs/bar                : is something we don't understand
#
# + [foo](<lang>/docs/bar/...) : leading slash missing for absolute path
#
# + [foo](docs/bar/...)        : leading slash missing for absolute path
#
# + {{ < api-reference page="" anchor="" ... > }}
# + {{ < api-reference page="" > }}

import argparse
import glob
import os
import re
import sys
from collections import namedtuple

# These are the bad links that doesn't hurt, though good to fix
BAD_LINK_TYPES = {
    "B01": {
        "reason": "Using bad protocol",
        "level": "WARNING",
    },
    "B02": {
        "reason": "Link target is a redirect entry",
        "level": "WARNING",
    },
    "B03": {
        "reason": "Intra-site linkes should use relative path",
        "level": "WARNING",
    },
}

# Constants for colored printing
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_GRAY = "\033[90m"
C_CYAN = "\033[36m"
C_END = "\033[0m"

# Command line arguments shared across functions
ARGS = None
# Command line parser
PARSER = None
# Language as parsed from the file path
LANG = None
# Global result dictionary keyed by page examined
RESULT = {}
# Cached redirect entries
REDIRECTS = {}
# Redirect entries in file order, including entries that do not perform a
# redirect (for example, custom 404 responses)
REDIRECT_RULES = []
# Duplicate redirect sources, recorded as (first rule, duplicate rule)
REDIRECT_DUPLICATES = []
# Cached anchors in target pages
ANCHORS = {}

RedirectRule = namedtuple(
    "RedirectRule", ["source", "target", "status", "line", "conditions"]
)
RedirectResolution = namedtuple(
    "RedirectResolution", ["final_target", "chain", "cycle", "terminal_status"]
)


def new_record(level, message, target):
    """Create new checking record.

    :param level: Record severity level, one of 'INFO', 'WARNING' and 'ERROR'
    :param message: Error message string
    :param target: The link target in question
    :returns: A string representation the checking result, may contain ASCII
              coded terminal colors, or None if the record is suppressed.
    """
    global ARGS

    # Skip info when verbose
    if ARGS.verbose is False and level == "INFO":
        return None

    result = None
    if ARGS.no_color:
        result = target + ": " + message
    else:
        target = C_GRAY + target + C_END
        if level == "INFO":
            result = target + ": " + C_GREEN + message + C_END
        elif level == "WARNING":
            result = target + ": " + C_YELLOW + message + C_END
        else:  # default to error
            result = target + ": " + C_RED + message + C_END

    return result


def dump_result():
    """Dump result to stdout."""
    global RESULT, ARGS

    for path, path_output in RESULT.items():
        norm_path = os.path.normpath(path)
        if ARGS.no_color:
            print("File: " + norm_path)
        else:
            print(C_CYAN + "File: " + norm_path + C_END)
        for p in path_output:
            print(" "*4 + p)
    return


def strip_comments(content):
    """Manual striping of comments from file content.

    Many localized content pages contain original English content in comments.
    These comments have to be stripped out before analyzing the links.
    Doing this using regular expression is difficult. Even the grep tool is
    not suitable for this use case.

    NOTE: We strived to preserve line numbers when producing the resulted
    text. This can be useful in future if we want to print out the line
    numbers for bad links.
    """
    result = []
    in_comment = False
    for line in content:
        idx1 = line.find("<!--")
        idx2 = line.find("-->")
        if not in_comment:
            # only care if new comment started
            if idx1 < 0:
                result.append(line)
                continue

            # single line comment
            if idx2 > 0:
                result.append(line[:idx1] + line[idx2+4:])
                continue
            result.append(line[:idx1])
            in_comment = True
            continue

        # already in comment block
        if idx2 < 0:  # ignore whole line
            result.append("")
            continue
        result.append(line[idx2+4:])
        in_comment = False

    return result


def normalize_filename(name, ftype="markdown"):
    """Guess the filename based on a link target.

    This function only deals with regular files.
    """
    if name.endswith("/"):
        name = name[:-1]
    if ftype == "markdown":
        name += ".md"
    else:
        name += ".html"
    return name


def check_file_exists(base, path, ftype="markdown"):
    """Check if the target file exists.

    NOTE: We build a normalized path using 'base' and 'path' values. Suppose
    the resulted path string is 'foo/bar', we check if 'foo/bar.md' exists,
    AND we check if 'foo/bar/_index.md' exists.

    :param base: The base directory to begin with
    :param path: The link target which is a relative path string
    :returns: A boolean indicating whether the target file exists.
    """
    # NOTE: anchor is ignored, can be a todo item
    parts = path.split("#")

    fn = normalize_filename(parts[0], ftype=ftype)
    target = base + fn

    if os.path.isfile(target):
        return True

    dir_name = base + parts[0]
    if os.path.isdir(dir_name):
        if os.path.isfile(dir_name + "/_index.md"):
            return True
        if os.path.isfile(dir_name + "/_index.html"):
            return True
        # /docs/contribute/style/hugo-shortcodes/ has this
        if os.path.isfile(dir_name + "/index.md"):
            return True
    return False


def strip_url_suffix(path):
    """Remove the query string and fragment from a URL path."""
    return path.split("#", 1)[0].split("?", 1)[0]


def is_external_url(target):
    """Return True when target names a network URL."""
    return target.startswith("http://") or target.startswith("https://")


def is_fixed_path(path):
    """Return True for an internal path without Netlify placeholders."""
    return (path.startswith("/") and
            "*" not in path and
            ":" not in path)


def redirect_status_code(status):
    """Return a status code without Netlify's force suffix."""
    return status.rstrip("!")


def is_redirect_status(status):
    """Return True for the status codes that cause an HTTP redirect."""
    return redirect_status_code(status) in {"301", "302", "303", "307", "308"}


def find_redirect_rule(path):
    """Find an exact fixed-path redirect rule.

    The existing checker accepted links with or without a trailing slash. Keep
    that behavior, while preserving the source spelling from `_redirects.base`.
    """
    target = strip_url_suffix(path)
    rule = REDIRECTS.get(target)
    if rule:
        return rule
    if target.endswith("/"):
        return REDIRECTS.get(target[:-1])
    return REDIRECTS.get(target + "/")


def generated_path_exists(site_root, path):
    """Check whether a URL path exists in a rendered Hugo site."""
    if not site_root or not is_fixed_path(path):
        return False

    path = strip_url_suffix(path)
    relative_path = path.lstrip("/")
    normalized = os.path.normpath(os.path.join(site_root, relative_path))
    site_root = os.path.abspath(site_root)
    normalized = os.path.abspath(normalized)
    if os.path.commonpath([site_root, normalized]) != site_root:
        return False

    candidates = [normalized]
    if path.endswith("/"):
        candidates.append(os.path.join(normalized, "index.html"))
    else:
        candidates.extend([normalized + ".html",
                           os.path.join(normalized, "index.html")])
    return any(os.path.isfile(candidate) for candidate in candidates)


def redirect_rule_applies(rule, site_root=None):
    """Return whether Netlify would apply an exact redirect rule.

    Unless a status code ends in ``!``, a generated file takes precedence over
    a redirect. This can only be determined when a rendered site is provided.
    """
    if rule.status.endswith("!"):
        return True
    if site_root and generated_path_exists(site_root, rule.source):
        return False
    return True


def resolve_redirect(path, site_root=None):
    """Resolve a fixed redirect chain without making network requests."""
    target = strip_url_suffix(path)
    chain = [target]
    visited = set()

    while True:
        rule = find_redirect_rule(target)
        if (rule is None or not is_redirect_status(rule.status) or
                not redirect_rule_applies(rule, site_root)):
            terminal_status = rule.status if rule else None
            return RedirectResolution(target, chain, False, terminal_status)

        if rule.source in visited:
            return RedirectResolution(target, chain, True, None)
        visited.add(rule.source)

        target = strip_url_suffix(rule.target)
        chain.append(target)
        if is_external_url(target):
            return RedirectResolution(target, chain, False, None)


def get_redirect(path):
    """Return the final target for an acyclic fixed redirect chain."""
    resolution = resolve_redirect(path)
    if (len(resolution.chain) == 1 or resolution.cycle or
            (resolution.terminal_status and
             not is_redirect_status(resolution.terminal_status))):
        return None
    return resolution.final_target


def parse_redirects(content):
    """Parse static redirect rules and retain Netlify's first-match order."""
    global REDIRECTS, REDIRECT_RULES, REDIRECT_DUPLICATES

    REDIRECTS = {}
    REDIRECT_RULES = []
    REDIRECT_DUPLICATES = []
    sources = {}

    for line_number, item in enumerate(content, start=1):
        stripped = item.strip()
        if not stripped or stripped.startswith("#"):
            continue

        parts = stripped.split()
        if len(parts) < 2:
            continue

        status = "301"
        condition_start = 2
        if len(parts) >= 3 and re.fullmatch(r"\d{3}!?", parts[2]):
            status = parts[2]
            condition_start = 3

        conditions = tuple(parts[condition_start:])
        rule = RedirectRule(parts[0], parts[1], status, line_number,
                            conditions)
        REDIRECT_RULES.append(rule)

        # Conditional rules cannot be resolved deterministically without a
        # request context, so retain them for line reporting but do not add
        # them to the exact-match lookup table.
        if rule.conditions:
            continue
        if rule.source in sources:
            REDIRECT_DUPLICATES.append((sources[rule.source], rule))
            continue
        sources[rule.source] = rule

        if not is_fixed_path(rule.source):
            continue

        # Netlify applies the first matching rule, so keep the first one.
        REDIRECTS[rule.source] = rule


def validate_redirects(site_root=None):
    """Warn about invalid fixed redirects that can be checked locally.

    Duplicate sources are safe to detect from the rules alone. Cycle and
    dangling-target checks require the rendered site so that Hugo aliases,
    generated pages, and Netlify's file-shadowing behavior are respected.
    Without a rendered site, only cycles made entirely from forced rules are
    reported.
    """
    records = []

    for first, duplicate in REDIRECT_DUPLICATES:
        if (first.target == duplicate.target and
                first.status == duplicate.status):
            detail = ("Duplicate redirect source; line %d is already handled "
                      "by line %d" % (duplicate.line, first.line))
        else:
            detail = ("Conflicting redirect source at line %d; Netlify uses "
                      "the first rule from line %d (%s -> %s)" %
                      (duplicate.line, first.line, first.source, first.target))
        records.append(new_record("WARNING", detail, duplicate.source))

    reported_cycles = set()
    for rule in REDIRECT_RULES:
        if (not is_fixed_path(rule.source) or rule.conditions or
                not is_redirect_status(rule.status)):
            continue

        resolution = resolve_redirect(rule.source, site_root)
        if resolution.cycle:
            if not site_root:
                cycle_rules = [
                    find_redirect_rule(path)
                    for path in resolution.chain[:-1]
                ]
                if not all(cycle_rule and cycle_rule.status.endswith("!")
                           for cycle_rule in cycle_rules):
                    continue
            cycle_key = frozenset(resolution.chain)
            if cycle_key not in reported_cycles:
                chain = " -> ".join(resolution.chain)
                records.append(new_record(
                    "WARNING", "Redirect cycle detected: " + chain,
                    rule.source))
                reported_cycles.add(cycle_key)
            continue

        if not site_root:
            continue

        # A custom 404 response is an intentional terminal result, not a
        # dangling redirect target.
        if redirect_status_code(resolution.terminal_status or "") == "404":
            continue

        final_target = resolution.final_target
        if (is_external_url(final_target) or
                not is_fixed_path(final_target)):
            continue
        if generated_path_exists(site_root, final_target):
            continue

        chain = " -> ".join(resolution.chain)
        records.append(new_record(
            "WARNING",
            "Redirect target does not exist in the rendered site "
            "(chain: %s)" % chain,
            rule.source))

    return [record for record in records if record]


def check_target(page, anchor, target):
    """Check a link from anchor to target on provided page.

    :param page: Currently not used. Passed here in case we want to check the
                 in-page links in the future.
    :param anchor: Anchor string from the content page. This is provided to
                help handle cases where target is empty.
    :param target: The link target string to check
    :returns: A checking record (string) if errors found, or None if we can
              find the target link.
    """
    target = target.strip()
    # B01: bad protocol
    if target.startswith("http://"):
        return new_record("WARNING", "Use HTTPS rather than HTTP", target)

    # full link
    if target.startswith("https://"):
        # B03: self link, should revise to relative path
        if (target.startswith("https://k8s.io/docs") or
                target.startswith("https://kubernetes.io/docs")):
            return new_record("ERROR", "Should use relative paths", target)
        # external link, skip
        return new_record("INFO", "External link, skipped", target)

    # in-page link
    # TODO: check if the target anchor does exists
    if target.startswith("#"):
        return new_record("INFO", "In-page link, skipped", target)

    # Link has shortcode
    if target.find("{{") > 0:
        return new_record("INFO", "Link has shortcode, skipped", target)

    # TODO: check links to examples
    if target.startswith("/examples/"):
        return new_record("WARNING", "Examples link, skipped", target)

    # it is an embedded image
    # TODO: an image might get translated as well
    if target.endswith(".png") or target.endswith(".svg"):
        return new_record("INFO", "Link to image, skipped", target)

    # link to English or localized page
    if (target.startswith("/docs/") or
            target.startswith("/" + LANG + "/docs/")):

        # target is shared reference (kubectl or kubernetes-api?
        if (target.find("/docs/reference/generated/kubectl/") >= 0 or
                target.find("/docs/reference/generated/kubernetes-api/") >= 0):
            if check_file_exists(ROOT + "/static", target, "html"):
                return None
            return new_record("ERROR", "Missing shared reference", target)

        # target is a markdown (.md) or a "<dir>/_index.md"?
        if target.startswith("/docs/"):
            base = os.path.join(ROOT, "content", "en")
        else:
            # localized target
            base = os.path.join(ROOT, "content")
        ok = check_file_exists(base, target)
        if ok:
            # We do't do additional checks for English site even if it has
            # links to a non-English page
            if LANG == "en":
                return None

            # If we are already checking localized link, fine
            if target.startswith("/" + LANG + "/docs/"):
                return None

            # additional check for localization even if English target exists
            base = os.path.join(ROOT, "content", LANG)
            found = check_file_exists(base, target)
            if not found:
                # Still to be translated
                return None
            msg = ("Localized page detected, please append '/%s' to the target"
                   % LANG)

            return new_record("ERROR", msg, target)

        # target might be a redirect entry
        redirect = resolve_redirect(target)
        if redirect.cycle:
            msg = "Link target is part of a redirect cycle: %s" % (
                " -> ".join(redirect.chain))
            return new_record("WARNING", msg, target)
        real_target = get_redirect(target)
        if real_target:
            msg = ("Link using redirect records, should use %s instead" %
                   real_target)
            return new_record("WARNING", msg, target)
        return new_record("ERROR", "Missing link for [%s]" % anchor, target)

    # absolute link missing leading slash
    if (target.startswith("docs/") or target.startswith(LANG + "/docs/")):
        return new_record("ERROR", "Missing leading slash. Try \"/%s\"" %
                                   target, target)

    msg = "Link may be wrong for the anchor [%s]" % anchor
    return new_record("WARNING", msg, target)


def check_anchor(target, anchor):
    """Check if an anchor is defined in the target page

    :param target: The target page to check
    :param anchor: Anchor string to find in the target page
    """
    if target not in ANCHORS:
        try:
            with open(target, "r") as f:
                data = f.readlines()
        except Exception as ex:
            print("[Error] failed in reading markdown file: " + str(ex))
            return
        content = "\n".join(strip_comments(data))
        anchor_pattern1 = r"<a name=\"(.*?)\""
        regex1 = re.compile(anchor_pattern1)
        anchor_pattern2 = r"{#(.*?)}"
        regex2 = re.compile(anchor_pattern2)
        ANCHORS[target] = regex1.findall(content) + regex2.findall(content)
    return anchor in ANCHORS[target]


def check_apiref_target(target, anchor):
    """Check a link to an API reference page.

    :param target: The link target string to check
    :param anchor: Anchor string from the content page
    """
    base = os.path.join(ROOT, "content", "en", "docs", "reference",
                        "kubernetes-api")
    ok = check_file_exists(base + "/", target)
    if not ok:
        return new_record("ERROR", "API reference page not found", target)

    if anchor is None:
        return

    target_page = os.path.join(base, target)+".md"
    if not check_anchor(target_page, anchor):
        return new_record("ERROR", "Anchor not found in API reference page",
                          target+"#"+anchor)


def validate_links(page, in_place_edit):
    """Find and validate links on a content page.

    The checking records are consolidated into the global variable RESULT.
    """
    try:
        with open(page, "r") as f:
            data = f.readlines()
    except Exception as ex:
        print("[Error] failed in reading markdown file: " + str(ex))
        return

    content = "\n".join(strip_comments(data))

    # Single results: searches for pattern: []()
    link_pattern = r"\[([`/\w\s\n]*)\]\(([^\)]*)\)"
    regex = re.compile(link_pattern)

    matches = regex.findall(content)
    records = []
    target_records = []
    for m in matches:
        r = check_target(page, m[0], m[1])
        if r:
            records.append(r)
            target_records.append(m[1])

    # if multiple records are the same they need not be checked repeatedly
    # remove paths that are not relative too
    target_records = {item for item in target_records
                         if not item.startswith("http") and
                          not item.startswith(f"/{LANG}")}

    # English-language pages don't have "en" in their path
    if in_place_edit and target_records and LANG != "en":
        updated_data = []
        for line in data:
            if any(rec in line for rec in target_records):
                for rec in target_records:
                    line = line.replace(
                        f"({rec})",
                        # assumes unlocalized links are in "/docs/..." format
                        f"(/{LANG}{rec})")
            updated_data.append(line)

        with open(page, "w") as f:
            for line in updated_data:
                f.write(line)

    # searches for pattern: {{< api-reference page="" anchor=""
    apiref_re = r"{{ *< *api-reference page=\"([^\"]*?)\" *anchor=\"(.*?)\""
    regex = re.compile(apiref_re)

    matches = regex.findall(content)
    for m in matches:
        r = check_apiref_target(m[0], m[1])
        if r:
            records.append(r)

    # searches for pattern: {{< api-reference page=""
    apiref_re = r"{{ *< *api-reference page=\"([^\"]*?)\""
    regex = re.compile(apiref_re)

    matches = regex.findall(content)
    for m in matches:
        r = check_apiref_target(m, None)
        if r:
            records.append(r)

    if len(records):
        RESULT[page] = records


def parse_arguments():
    """Argument parser.

    Result is returned and saved into global variable ARGS.
    """
    global PARSER

    PARSER = argparse.ArgumentParser(description="Links checker for docs.")
    PARSER.add_argument("-v", dest="verbose", action="store_true",
                        help="switch on verbose level")
    PARSER.add_argument("-n", "--no-color", action="store_true",
                        help="Suppress colored printing.")
    PARSER.add_argument("-f", dest="filter", default="content/en/docs/**/*.md",
                        metavar="<FILTER>",
                        help=("File pattern to scan. "
                              "(default='content/en/docs/**/*.md')"))
    PARSER.add_argument("-w", dest="in_place_edit", action="store_true",
                        help="[EXPERIMENTAL] Turns on in-place replacement "
                             "for localized content.")
    PARSER.add_argument("--check-redirects", action="store_true",
                        help=("Warn about duplicate and cyclic redirect "
                              "rules, and with --site-root, dangling "
                              "targets."))
    PARSER.add_argument("--redirects-file", metavar="<FILE>",
                        help=("Redirect rules to check (default: "
                              "static/_redirects.base)."))
    PARSER.add_argument("--site-root", metavar="<DIR>",
                        help=("Rendered site directory used to check redirect "
                              "targets and file shadowing."))

    return PARSER.parse_args()


def main():
    """The main entry of the program."""
    global ARGS, ROOT, PARSER, LANG

    ARGS = parse_arguments()
    ROOT = os.path.join(os.path.dirname(__file__), '..')

    print(ARGS.filter)
    parts = ARGS.filter.split("/", 2)
    if len(parts) != 3 or parts[0] != "content":
        print("ERROR:\nPlease specify file pattern in the format "
              "'content/<lang>/<path-pattern>', for example:\n"
              "'content/zh-cn/docs/concepts/**/*.md'\n")
        PARSER.print_help()
        sys.exit(-1)

    LANG = parts[1]

    if ARGS.site_root and not ARGS.check_redirects:
        PARSER.error("--site-root requires --check-redirects")
    if ARGS.site_root and not os.path.isdir(ARGS.site_root):
        PARSER.error("--site-root must name a rendered site directory")

    # read redirects data
    redirects_fn = (ARGS.redirects_file or
                    os.path.join(ROOT, "static", "_redirects.base"))
    try:
        with open(redirects_fn, "r") as f:
            data = f.readlines()
        parse_redirects(data)

    except Exception as ex:
        print("[Error] failed in reading redirects file: " + str(ex))
        return

    if ARGS.check_redirects:
        redirect_records = validate_redirects(ARGS.site_root)
        if redirect_records:
            RESULT[redirects_fn] = redirect_records

    folders = [f for f in glob.glob(ARGS.filter, recursive=True)]
    for page in folders:
        validate_links(page, ARGS.in_place_edit)

    dump_result()

    # Done
    print("Completed link validation.")


if __name__ == '__main__':
    sys.exit(main())
