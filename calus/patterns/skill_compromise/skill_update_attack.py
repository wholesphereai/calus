"""skill-compromise: skill-update-attack  (4 patterns)"""

PATTERNS = [
    ('(?i)(version[_\\-\\s]?(changed|updated|bumped|mutated)|new[_\\-\\s]?version[_\\-\\s]?available|skill[_\\-\\s]?updated)', 'high', ''),
    ('(?i)(additional[_\\-\\s]?permissions?[_\\-\\s]?required|scope[_\\-\\s]?expanded|capabilities?[_\\-\\s]?added|new[_\\-\\s]?permissions?)', 'high', ''),
    ('(?i)(re-?authenticate|re-?authorize|grant[_\\-\\s]?access|approve[_\\-\\s]?permissions?|accept[_\\-\\s]?new[_\\-\\s]?terms)', 'high', ''),
    ('(?i)(migration[_\\-\\s]?required|data[_\\-\\s]?transfer|export[_\\-\\s]?before[_\\-\\s]?update|backup[_\\-\\s]?your[_\\-\\s]?data[_\\-\\s]?to)', 'high', ''),
]