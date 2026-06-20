"""Transform-evasion detection layer. Catches obfuscated attacks."""
from calus.detection.transforms.ascii_smuggle import detect as ascii_smuggle_detect  # noqa
from calus.detection.transforms.atbash import detect as atbash_detect  # noqa
from calus.detection.transforms.binary import detect as binary_detect  # noqa
from calus.detection.transforms.braille import detect as braille_detect  # noqa
from calus.detection.transforms.charspace import detect as charspace_detect  # noqa
from calus.detection.transforms.charswap import detect as charswap_detect  # noqa
from calus.detection.transforms.flip import detect as flip_detect  # noqa
from calus.detection.transforms.morse import detect as morse_detect  # noqa
from calus.detection.transforms.zalgo import detect as zalgo_detect  # noqa
