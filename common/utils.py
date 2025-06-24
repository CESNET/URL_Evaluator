import regex


# Regex used to validate URLs
url_validator_regex = regex.compile(r"""
    ^                     # Start of string
    https?://             # Scheme
    [a-zA-Z0-9.-]+        # Hostname or domain
    (?::[0-9]+)?          # Optional port
    (?:/[^\s?#]*)?        # Optional path
    (?:\?[^\s#]*)?        # Optional query string
    (?:\#[^\s]*)?         # Optional fragment
    (?:\$\S*)?            # Optional $suffix
    $                     # End of string
""", regex.VERBOSE)


# Regex used to capture URLs found in shell commands
url_capture_regex = regex.compile(r"""
    (?<!                                  # Negative lookbehind (skip URLs after these flags):
        (?:--referer|-e)                  #   --referer or -e option
        (?:\s|'\s|"|\s'|\s")              #   followed by space or quoted space
    )
    (                                     # Capturing group: the URL itself
        https?://                         #   http:// or https://
        .*?                               #   non-greedy match of everything after
    )
    (?=                                   # Positive lookahead: stop match at
        \s | ; | \| | \\\\ | " | ' | $    #   whitespace, semicolon, pipe, backslash, quote, or end of string
    )
""", regex.VERBOSE)


# Regex used to capture shell commands in downloaded content
command_capture_regex = regex.compile(r"""
    (.*                            # Capture the entire line or command
        \b(?:curl|wget)\b          # Match 'curl' or 'wget' as whole words
        .*                         # Any characters (greedy) in between
        https?://[^\s]+            # A URL starting with http or https, up to the next space
        .*
    )
""", regex.VERBOSE)


def extract_urls(command: str):
    """
    Extract URLs from shell commands
    """
    return [url.strip() for url in url_capture_regex.findall(command)]


def extract_commands(content: str):
    """
    Extract shell commands from downloaded content
    """
    return [cmd.strip() for cmd in command_capture_regex.findall(content)]


def is_valid(url: str):
    """
    Check whether a URL is valid
    """
    return url_validator_regex.match(url) is not None
