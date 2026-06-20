"""skill-compromise: unsafe-model-artifact-load  (5 patterns)"""

PATTERNS = [
    ('pickle\\.(?:load|loads|Unpickler)\\s*\\(', 'critical', 'Python pickle.load/loads/Unpickler call — direct invocation of unsafe deserialization; any pickle.load on untrusted model files can execute '),
    ('hf_hub_download\\s*\\([^)]{0,200}\\.(?:pkl|pickle|pt|pth|exe|so|dll|dylib)\\b', 'critical', 'hf_hub_download() with dangerous file extension in the path — direct HuggingFace Hub download of a pickle/PyTorch/executable artifact; llm-probe-framework'),
    ('(?:torch\\.load|torch\\.hub\\.load|joblib\\.load|dill\\.load|cloudpickle\\.load)\\s*\\(\\s*[\'"]?[^\'")\\s]{1,120}\\.(?:pkl|pickle|pt|pth|bin)\\b', 'critical', 'torch.load / joblib.load / dill.load with explicit .pkl/.pt/.bin path — PyTorch-format and joblib model files are pickle-based; torch.load w'),
    ('list_repo_files\\s*\\(\\s*[\'"][\\w/.-]{3,80}[\'"]', 'critical', 'huggingface_hub.list_repo_files("org/model-name") — llm-probe-framework HF_Files probe trigger pattern; a tool response enumerating repo files to identify'),
    ('(?:download|load|run|execute|import)\\s+[\\w./-]{1,100}\\.(?:exe|so|dll|dylib)\\b[\\s\\S]{0,100}(?:model|weight|artifact|checkpoint)', 'critical', 'Loading native binary (.exe/.so/.dll/.dylib) from a model/weights/checkpoint context — HF_Files extended_detectors.FileIsExecutable pattern;'),
]