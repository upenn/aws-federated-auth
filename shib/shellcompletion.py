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
    local cur profiles prefix
    cur="${COMP_WORDS[COMP_CWORD]}"
    prefix="AWS_PROFILE="

    if [[ ${#COMP_WORDS[@]} -eq 2 ]]; then
        # Assume = is not broken into separate word
        # Only trigger completion if the command starts with `export AWS_PROFILE=`
        if [[ ${COMP_WORDS[0]} == "export" && ${COMP_WORDS[1]} == "AWS_PROFILE="* ]]; then
            # Extract profile names from ~/.aws/credentials
            profiles=$(grep '^\[' ~/.aws/credentials 2>/dev/null | sed 's/^\[\(.*\)\]$/\\1/')

            COMPREPLY=( $(compgen -W "${profiles}" -- "${cur#${prefix}}") )
        fi
    elif [[ ${#COMP_WORDS[@]} -gt 2 ]]; then
        # Assume = is broken into separate word
        # Only trigger completion if the command starts with `export AWS_PROFILE=`
        if [[ ${COMP_WORDS[0]} == "export" && ${COMP_WORDS[1]} == "AWS_PROFILE" && ${COMP_WORDS[2]} == "="* ]]; then
            # Extract profile names from ~/.aws/credentials
            profiles=$(grep '^\[' ~/.aws/credentials 2>/dev/null | sed 's/^\[\(.*\)\]$/\\1/')
            
            if [[ ${cur} == "=" ]]; then
                cur=""
            fi

            COMPREPLY=( $(compgen -W "${profiles}" -- "${cur}") )
        fi
    fi
}

# Register the completion for the `export` command
complete -F _aws_profile_complete export
"""

    ########## Class methods ##########
    def install_completion(
        self,
        shell_type: str,
        completion_location: str = None
    ):
        """Install the shell completion script for the specified shell type."""
        if shell_type not in ('bash', 'omz'):
            raise ValueError("Unsupported shell type. Use 'bash' or 'omz'.")
        
        if shell_type == 'bash':
            self._install_bash_completion(completion_location)
        elif shell_type == 'omz':
            self._install_omz_completion(completion_location)
        return

    def _install_bash_completion(self, completion_location: str = None):
        """Install the bash completion script."""
        if not completion_location:
            completion_location = '~/._aws_profile_complete.sh'
        # Confirm that the location exists
        os.makedirs(os.path.dirname(os.path.expanduser(completion_location)), exist_ok=True)
        
        # Check if file exists, create if not
        if not os.path.exists(os.path.expanduser(completion_location)):
            with open(os.path.expanduser(completion_location), 'w') as f:
                f.write(self._bash_completion_script)
            logger.debug(f"Bash completion script:\n{self._bash_completion_script}")
            print(f"Bash completion script installed at {completion_location}")
        else:
            # Check if script is already present
            with open(os.path.expanduser(completion_location), 'r') as f:
                content = f.read()
            if '_aws_profile_complete()' in content:
                logger.error(f"Bash completion script _aws_profile_complete() already exists in {completion_location}.\n"
                              "No changes made.\n"
                              "If you want to update it, please remove the existing script first.")
                return
            else: # Add script to end of existing file
                with open(os.path.expanduser(completion_location), 'a') as f:
                    f.write('\n' + self._bash_completion_script)
                logger.debug(f"Bash completion script:\n{self._bash_completion_script}")
                print(f"Bash completion script appended to {completion_location}")
                
        # Source the completion script in .bashrc
        # Ask for user confirmation to add sourcing line
        add_source = input(f'To automatically load the completion script on terminal start, `source {completion_location}` needs to be added to your .bashrc file.\n'
                           'Do you want to add this line? (y/n): ').strip().lower()
        if add_source == 'y':
            if not os.path.exists(os.path.expanduser('~/.bashrc')):
                with open(os.path.expanduser('~/.bashrc'), 'w') as f:
                    f.write(f'source {os.path.expanduser(completion_location)}\n')
            else:
                with open(os.path.expanduser('~/.bashrc'), 'a') as f:
                    f.write(f'\nsource {os.path.expanduser(completion_location)}\n')
            print("Source line added to your .bashrc file.")
        else:
            print("You can manually add the following line to your .bashrc file to enable completion on terminal start:")
            print(f'source {os.path.expanduser(completion_location)}')

        print("Please restart your terminal to apply changes.")
        return
    
    def _install_omz_completion(self, completion_location: str = None):
        """Install the oh-my-zsh completion script."""
        if not completion_location:
            completion_location = '~/.oh-my-zsh/custom/completions/_aws_profile_export'
        # Confirm that the location ends in `_aws_profile_export`
        if not completion_location.endswith('_aws_profile_export'):
            logger.error(f"Completion location must end with '_aws_profile_export'.")
            return
        # Confirm that location exists
        os.makedirs(os.path.dirname(os.path.expanduser(completion_location)), exist_ok=True)
            
        # Check if file exists, create if not
        if not os.path.exists(os.path.expanduser(completion_location)):
            with open(os.path.expanduser(completion_location), 'w') as f:
                f.write(self._omz_completion_script)
            logger.debug(f"oh-my-zsh completion script:\n{self._omz_completion_script}")
            print(f"oh-my-zsh completion script installed at {completion_location}")
            print("Please restart your terminal or run `omz reload` to apply changes.")
        else:
            logger.error(f"oh-my-zsh completion script _aws_profile_export() already exists in {completion_location}.\n"
                          "No changes made.\n"
                          "If you want to update it, please remove the existing script first.")
            
        return