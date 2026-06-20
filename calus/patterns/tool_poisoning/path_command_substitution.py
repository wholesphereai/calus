"""tool-poisoning: path-command-substitution  (1 patterns)"""

PATTERNS = [
    ('(?<![A-Za-z_])(?:file_?path|filename|input_file|output_file|target_file|source_file|file|path|source|destination|target)["\']?\\s*[:=]\\s*["\'][^"\']{0,500}(?:\\$\\([^)]{1,300}\\)|`[^`]{1,300}`)', 'critical', 'Path-shaped argument key (file_path / filename / path / source / target / input_file / output_file / destination) bound via : or = to a stri'),
]