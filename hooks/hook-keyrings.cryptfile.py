from PyInstaller.utils.hooks import collect_submodules, copy_metadata

# Collect backends
hiddenimports = collect_submodules('keyrings.cryptfile')

# Keyring performs backend plugin discovery using setuptools entry points, which are listed in the metadata. Therefore,
# we need to copy the metadata, otherwise no backends will be found at run-time.
datas = copy_metadata('keyrings.cryptfile')
