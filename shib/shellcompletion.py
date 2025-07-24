"""Shell completion add-on scripts for `export AWS_PROFILE` command."""
import os
import logging

logger = logging.getLogger(__name__)
logger.setLevel(level=os.environ.get("LOGLEVEL", "INFO"))
logger.propagate = False
log_channel = logging.StreamHandler()
formatter = logging.Formatter('{"time":"%(asctime)s","name":"%(name)s","level":"%(levelname)8s","message":"%(message)s"}',"%Y-%m-%d %H:%M:%S")
log_channel.setFormatter(formatter)
logger.addHandler(log_channel)

class ShellCompletion:
    """Shell completion for AWS profile export command."""

    def __init__(
        self,
        loglevel=None
    ):
        """Initialize the ShellCompletion instance."""
        if loglevel:
            logger.setLevel(logging.getLevelName(loglevel.upper()))

    ########## Shell completion scripts ##########
    _omz_completion_script = """#compdef export
# `export AWS_PROFILE="` completion script for aws-federated-auth

_aws_profile_export() {
  local cur curval profiles matches

  # grab the word under the cursor
  cur=${words[CURRENT]}

  # only do our thing if they're completing AWS_PROFILE=
  if [[ $cur == AWS_PROFILE\=\"* ]]; then
    # strip off the whole "AWS_PROFILE=" prefix
    curval=${cur#AWS_PROFILE=\"}

    # pull all profiles from ~/.aws/credentials
    # filter for the current value
    # add end quote to each profile
    profiles=(${(f)"$(grep "^\[$curval" ~/.aws/credentials 2>/dev/null \
                   | sed -e 's/^\[\(.*\)\]$/\1\"/')"})
    
    compadd -Q -P AWS_PROFILE=\" -U -- ${profiles[@]}
    return
  fi

  # fallback to the standard export/typeset completion
  _typeset "$@"
}
"""
    _bash_completion_script = """# `export AWS_PROFILE=` completion script for aws-federated-auth

_aws_profile_complete() {
    local cur profiles
    cur="${COMP_WORDS[COMP_CWORD]}"
    
    # Only trigger completion if the command starts with `export AWS_PROFILE=`
    if [[ ${COMP_WORDS[0]} == "export" && ${COMP_WORDS[1]} == "AWS_PROFILE="* ]]; then
        # Extract profile names from ~/.aws/credentials
        profiles=$(grep '^\[' ~/.aws/credentials 2>/dev/null | sed 's/^\[\(.*\)\]$/\1/')

        # Remove existing value if partially typed like AWS_PROFILE=abc
        local prefix="${COMP_WORDS[1]%%=*}="

        COMPREPLY=( $(compgen -W "${profiles}" -- "${cur#${prefix}}") )
    fi
}

# Register the completion for the `export` command
complete -F _aws_profile_complete export
"""

    ########## Class methods ##########
    def install_completion(
        self,
        shell_type: str
    ):
        """Install the shell completion script for the specified shell type."""
        if shell_type not in ('bash', 'omz'):
            raise ValueError("Unsupported shell type. Use 'bash' or 'omz'.")
        
        if shell_type == 'bash':
            self._install_bash_completion()
        elif shell_type == 'omz':
            self._install_omz_completion()
        return

    def _install_bash_completion(self):
        """Install the bash completion script."""
        file_location = '~/.bash_completion'
        
        # Check if file exists, create if not
        if not os.path.exists(os.path.expanduser(file_location)):
            with open(os.path.expanduser(file_location), 'w') as f:
                f.write(self._bash_completion_script)
            logger.debug(f"Bash completion script:\n{self._bash_completion_script}")
            print(f"Bash completion script installed at {file_location}")
        else:
            # Check if script is already present
            with open(os.path.expanduser(file_location), 'r') as f:
                content = f.read()
            if '_aws_profile_complete()' in content:
                logger.error(f"Bash completion script _aws_profile_complete() already exists in {file_location}.\n"
                              "No changes made.\n"
                              "If you want to update it, please remove the existing script first.")
                return
            else: # Add script to end of existing file
                with open(os.path.expanduser(file_location), 'a') as f:
                    f.write('\n' + self._bash_completion_script)
                logger.debug(f"Bash completion script:\n{self._bash_completion_script}")
                print(f"Bash completion script appended to {file_location}")
                
        print("Please restart your terminal or run `source ~/.bash_completion` to apply changes.")
        return
    
    def _install_omz_completion(self):
        """Install the oh-my-zsh completion script."""
        file_location = '~/.oh-my-zsh/custom/completions/_aws_profile_export'
        
        # Check if file exists, create if not
        if not os.path.exists(os.path.expanduser(file_location)):
            with open(os.path.expanduser(file_location), 'w') as f:
                f.write(self._omz_completion_script)
            logger.debug(f"oh-my-zsh completion script:\n{self._omz_completion_script}")
            print(f"oh-my-zsh completion script installed at {file_location}")
            print("Please restart your terminal or run `omz reload` to apply changes.")
        else:
            logger.error(f"oh-my-zsh completion script _aws_profile_export() already exists in {file_location}.\n"
                          "No changes made.\n"
                          "If you want to update it, please remove the existing script first.")
            
        return